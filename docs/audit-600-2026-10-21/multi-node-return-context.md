# MN006 — P2: opening a node restores an older route configuration on return

After a node is focused, changing and successfully submitting a different route
does not refresh that node's navigation links. **Open P1** still carries the
older route query in `return_to`. Following **Back to multi-node topology**
then restores the old scenario, direction and routing context instead of the
route the user just inspected. Refocusing the same P1 through the current
route's hop refreshes the links and makes the next round trip preserve the
current configuration.

This is one navigation-context finding. The node identity and revision remain
correct; the defect is the stale return query. The forced `#fabric` fragment is
related navigation scope, not a second counted bug.

## Browser evidence

The primary auditor performed the browser actions. This note's author reviewed
the saved DOM/URL evidence and source at `112d346`; no additional browser
execution or production-function probe is claimed here.

- [MX009: deliberate failure and refocus recovery](../../.runtime/audit-600-2026-10-21/multi-node/MX009.json),
  recorded at `2026-10-21T07:18:21.765Z`, contains the confirming sequence.
- [M081: preceding nested-VPN Return run](../../.runtime/audit-600-2026-10-21/multi-node/M081.json)
  establishes the route in use before the incidental first node opening.
- [Execution ledger](multi-node-results.jsonl) records MX009's failed current
  return-context assertions and successful refocus recovery.

All indexes below refer to MX009's zero-based `states` array.

| State | Recorded observation | Evidentiary scope |
|---|---|---|
| 0–1 | The first node opening and return contain `cross-node-mpls-label-mismatch`, Both directions and Return focus, although the preceding run was nested VPN Return. | Discovery context only. The first opening arose during a pointer-control attempt; it is not relied on as the deliberate reproduction. |
| 2 | `packet-native-ip`, Forward only, IPv4 family/type; visible resolved Forward path, no error, run enabled and `loadingHidden=true`. | The newer route really completed before navigation. |
| 3 | Current page URL is native IP Forward. Both the header and detail-panel node hrefs still encode MPLS mismatch / Both / Return focus in `return_to`. | Direct DOM evidence of stale links, before leaving the page. |
| 4–5 | Deliberate **Open P1** reaches `/node`; its Back link leads to a page whose enabled controls contain the older MPLS scenario, Both directions and MPLS family/type. | Actual return restores the wrong configuration; this is not merely unused link metadata. |
| 6 | Native IP Forward is submitted again and reaches the same settled, visible result. | Recovery control starts from a completed current trace. |
| 7 | After refocusing P1 through its current hop, both node hrefs encode native IP Forward, the current IPv4 context and current path ID. | Refocus regenerates the return query without changing the intended route. |
| 8 | The subsequent actual Open/Back round trip restores native IP Forward and IPv4 family/type in enabled controls. | Configuration preservation recovers after refocus. |

States 1, 5 and 8 contain no visible route result and record
`loadingHidden=false`, even though the form controls and run button are
enabled. They establish which configuration the returned page restored; they
do **not** establish that a trace on the returned page already completed.
States 2 and 6 provide the settled pre-navigation route evidence. No screenshot,
CPU, memory or navigation-latency measurement is attached to this finding.

## Reproduction and expected result

1. In the existing multi-node demo, run the MPLS handoff-mismatch scenario in
   Both directions, select Return and focus P1, establishing its node links.
2. Without refocusing the device, select `packet-native-ip`, Forward only and
   the compatible IPv4 context. Submit and wait for the resolved result.
3. Compare the current URL with the header **Open P1** link's decoded
   `return_to`. The current URL contains native IP Forward; the link retains
   the earlier MPLS route configuration.
4. Open P1 through that header link, then use **Back to multi-node topology**.
   The restored controls show the older scenario and direction.
5. Run native IP Forward again, focus P1 through its current route hop, and
   repeat the node round trip. The current scenario and direction now survive.

Opening a node should preserve the current route configuration for the return
trip. A user should not need to reselect an already focused device after every
route edit. This expectation concerns the captured query and configuration;
it does not require the returned page to reuse an in-memory route result.

## Source diagnosis

[Topology navigation code](../../frontend/assets/topology.js) builds
`currentReturnTarget()` from `location.href` at lines 9071–9084.
`navigationHref()` attaches that result as `return_to` when generating a link
(lines 9137–9157). These are snapshots of the URL at link-generation time.

`renderNodeDetail()` assigns `#mn-open-node.href`, then copies it to
`#mn-header-open-node.href` at lines 9178–9182. It also constructs resource
Timeline links in the same render. `focusNode()` synchronizes the URL before
calling this renderer (lines 9638–9647), which explains the observed repair
when P1 is refocused.

Route-only changes follow another render path:

- Scenario change invalidates the old route and calls `syncUrl()` at
  lines 9913–9936.
- Direction, selected path and graph-mode changes update route rendering and
  URL state at lines 4641–4663 and 5308–5368.
- A completed `runRouteTrace()` renders route/map/table content and calls
  `syncUrl()` at lines 9788–9795.

Those paths do not refresh the node navigation hrefs. `syncUrl()` itself ends
with `history.replaceState()` at line 9727 and does not update existing links.
The URL can therefore be current while the header and node-detail links retain
a previous route query indefinitely.

The [node workspace](../../frontend/assets/app.js), lines 488–497, validates
the supplied local return target and uses it for **Back to multi-node topology**
and the Fabric link. It faithfully follows the stale query supplied by the
topology page; the observed failure does not require a node-router lookup or
revision-identity failure.

`currentReturnTarget()` also assigns `#fabric` unconditionally. Both failed and
recovered round trips exhibit that fragment, so it does not explain why one
restores MPLS and the other native IP. It is retained as related scope only.

## Narrow repair and validation target

Keep the existing node navigation mechanism, but refresh its hrefs when the
canonical return context changes. The links should reflect the current route
without requiring node refocus or rerendering the whole detail panel. Preserve
normal anchor behavior, including opening a link in another tab. No additional
plug-in hook or navigation API is needed.

A regression should enter through the actual route-change/submit handlers:
focus a node in one route, submit another scenario/direction, compare both
node hrefs with the current configuration, and exercise the return. Repeat
with selected-path and graph-mode changes, then the existing refocus control.
Check resource Timeline and device-index Open links as related consumers;
their generation uses the same snapshot helper, but a stale round trip through
those individual links has not yet been demonstrated here. Header navigation
was exercised; the detail-panel href mismatch was directly observed without a
separate detail-panel click trial.

## Earlier coverage and limits

The [2026-10-20 manual audit](../manual-browser-audit-2026-10-20.md), line 167,
records a successful PE-B round trip preserving route configuration. That
single successful route does not cover changing route state after the node
links were generated. No earlier recorded finding matching this stale-return
sequence was located in the reviewed audit documents.

The [API contract](../api-contract.md), lines 3924–3928, describes node actions
whose return URL restores the same path. This finding identifies a browser
link-refresh failure within that existing behavior, not a new public contract.
Only this audit note was added for the finding. The plug-in-documentation drift
check found no author-visible behavior change requiring maintained authoring
documentation or skill updates at this audit-only stage.
