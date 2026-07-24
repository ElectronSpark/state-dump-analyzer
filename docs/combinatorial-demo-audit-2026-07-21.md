# Combinatorial demo audit — 2026-07-21

This audit deliberately separated discovery from repair. No source files were edited until the discovery matrix closed.

## Coverage

- 76 topology API combinations across profiles, perspectives, absolute/relative bases, clock policies, node subsets, ordering, and invalid selector shapes.
- 84 route combinations across every advertised scenario, direction, policy, focused/all-path presentation, and terminal/dead alternatives.
- 282 route-table filter and pagination combinations.
- All 434 advertised route-row `trace_query` actions and all 40 candidate paths.
- Browser checks for all topology element presets and representative custom layer sets, node subsets, query races, route scenarios, strict/best-effort missing-state handling, direction isolation, route filters, range selection, ESC clearing, zoom/density behavior, correlation scope, and the 125,000-event node workspace.

## Confirmed defects

The tables below freeze each defect at discovery closure, so their row status remains `open`. The final repair disposition is recorded by ID under **Repair verification**; no confirmed item was deferred.

### Multi-node API and fixture

| ID | Severity | Defect / failing combination | Status |
|---|---|---|---|
| API-01 | High | Link IDs change with `node_ids` ordering; four of six A/P1/B permutations leave route boundaries unresolved, and 20 default links contain only 19 unique IDs. | open |
| API-02 | High | One of 434 advertised row actions (`node-c ... asymmetric-scenario-active`) submits a focus path that is not a candidate. | open |
| API-03 | High | Fixed-scenario overrides and generated counterpart requests can advertise a route type/VRF that disagrees with the actual path. | open |
| API-04 | High/Medium | Endpoint membership in advertised VRF `node_ids` is not enforced. | open |
| API-05 | Medium | Fixed scenarios silently replace an explicit destination instead of rejecting an incompatible endpoint. | open |
| API-06 | Medium | Duplicate `203.0.113.0/24` destinations resolve to the wrong resource without stable endpoint identity. | open |
| API-07 | Medium | Equivalent bases (omitted vs `utc`, omitted vs zero offset, accepted aliases) fail frozen-context equality. | open |
| API-08 | Medium | Conflicting route-table `topology_context_id` and `context_id` values are silently accepted. | open |
| API-09 | Medium | Route-table cursors are plain offsets and can be reused across unrelated filters/contexts. | open |
| API-10 | Medium/Low | Duplicate, conflicting, or explicitly empty topology selectors are accepted. | open |
| API-11 | Low | Falsy wrong JSON types such as `basis: []` bypass object validation. | open |
| API-12 | Medium | Remote multi-hop loopbacks are incorrectly emitted as connected/on-link routes. | open |
| API-13 | Medium | Six advertised routing contexts have no route-table evidence. | open |

### Multi-node web workspace

| ID | Severity | Defect / failing combination | Status |
|---|---|---|---|
| WEB-01 | Critical | `connected-external-subnet` is rejected solely because router and its connected subnet share `node_id`. | open |
| WEB-02 | High | A route whose endpoints are outside the reconstructed node subset can produce a non-empty candidate set but a completely blank all-path graph. | open |
| WEB-03 | High | Duplicate datalist values discard endpoint IDs; Blue service and PE-E external subnet cannot be distinguished. | open |
| WEB-04 | High | A slower route response overwrites controls changed while the request is in flight. | open |
| WEB-05 | High | Reconstruction, auto-trace, and overlapping traces have stale-response/pending-state races. | open |
| WEB-06 | High/perf | Topology startup downloads and parses the 67,879,724-byte `/api/demo` event payload for two metadata fields. | open |
| WEB-07 | High/Medium | A selected-but-unusable stale FIB path is counted and grouped as active. | open |
| WEB-08 | Medium/High | “Selected-path evidence” renders trace-wide completeness/consistency instead of selected-path quality. | open |
| WEB-09 | Medium | Focused-path route-table highlighting includes rows from every candidate. | open |
| WEB-10 | Medium | Nested compound references collide because canonical JSON only sorts top-level keys. | open |
| WEB-11 | Medium | Invalid basis/policy URL parameters become empty selectors and invalid requests instead of defaults. | open |
| WEB-12 | Medium | Query failure still displays the ready API banner. | open |
| WEB-13 | Medium | Changing profile/perspective mutates the capability index before the new reconstruction is applied. | open |
| WEB-14 | Medium | VPN/Underlay presentation view is not deep-linked or restored. | open |
| WEB-15 | Medium | `focus_resource` is parsed but neither applied nor reliably removed. | open |
| WEB-16 | Medium | Two graph resize observers cancel each other through one shared animation-frame slot. | open |
| WEB-17 | Medium | Explicit graph focus targets replace stable fallback targets, breaking mixed plug-in correlation. | open |
| WEB-18 | Medium | Stale-FIB hardware-observed and control-expected alternatives are flattened into generic primary/standby labels. | open |
| WEB-19 | Low/Medium | Trace failure leaves requested-path, preview, and hover state behind; old results also remain visible after errors. | open |
| WEB-20 | Low | Negative subsecond times lose their sign. | open |

### Verification-only regression

| ID | Severity | Defect / failing combination | Discovery status |
|---|---|---|---|
| WEB-21 | Medium | After destination identity became strict, `router-to-router` still inherited the global Blue-service destination; its UI request therefore failed as an ambiguous `203.0.113.0/24` instead of selecting two router endpoints. | fixed during replay |

### Individual-node 125K-event workspace

| ID | Severity | Defect / failing combination | Status |
|---|---|---|---|
| NODE-01 | High | “Show all correlations” can drop the selected scale resource and hides server truncation. | open |
| NODE-02 | High | Timeline clusters never de-cluster as the graph zooms (88 clusters/34 individual marks at both 1x and 10x). | open |
| NODE-03 | High/perf | Unbounded zoom creates up to one density DOM button per event and can freeze the page. | open |
| NODE-04 | High | PE-B/D/E/P1/P2/C/CE deep links all load node-A’s `/api/demo` workspace. | open |
| NODE-05 | High | Correlated lanes use only the current graph and omit historical next-hop/dependency targets. | open |
| NODE-06 | High | Combined lanes can show zero spans for a selected resource that has current graph edges. | open |
| NODE-07 | Medium | One global 5,000-mark budget lets broad record rules starve later exact Ctrl-click jump lanes. | open |
| NODE-08 | Medium | Range overlap treats exclusive interval ends as inclusive, highlighting both old and new state at a transition. | open |
| NODE-09 | Medium | A whole collapsed cluster is highlighted when only some contained events intersect the selected range. | open |
| NODE-10 | Medium | Timeline fetches have no generation guard and can apply stale lane/rule responses. | open |
| NODE-11 | Medium | Dashboard layout persistence is global rather than revision/plugin-schema scoped. | open |
| NODE-12 | Medium | Nested relationship tooltip direction is calculated against the global root, not immediate parent. | open |
| NODE-13 | Medium | Duplicate tree instances are collapsed by resource ID when drawing relationship overlays. | open |
| NODE-14 | Low/Medium | Hover time-tag alignment ignores the sticky 280px label column. | open |
| NODE-15 | Low | Timeline expansion silently stops at depth six without an omitted-child affordance. | open |
| NODE-16 | Low | Space selects a standard resource row and also scrolls the page. | open |
| NODE-17 | Low | Combined-lane counter can claim two lanes when the association lane is absent/collapsed. | open |

## Discovery observations that passed

- Manual range `+120.000 s` to `+121.000 s` reported 1,001 events and grouped only range rows at the start of the virtualized event list.
- Escape cleared the range and selected-event state.
- Strict missing-node and missing-intermediate traces remained unresolved; best-effort variants preserved explicit assumptions.
- Forward-only and return-only validation correctly isolated the one-way service failure.
- Compact, all, no-layer, subnet-only, structural-only, and all-without-subnet topology projections rendered without errors and kept URL layer state in sync.
- Single-node, CE-only, partial multihoming, and full node reconstructions worked; an empty explicit UI selection was rejected without destroying the prior result.

## Repair verification

- **API-01 through API-13: fixed.** Topology link identity is canonical and order-independent; selector/basis/context/cursor inputs are validated and canonicalized; all returned route rows have executable actions; route scope, destination identity, connected routes, and advertised routing-context evidence are consistent.
- **WEB-01 through WEB-21: fixed.** The topology page uses a lightweight bootstrap, keeps applied and pending state separate, aborts/ignores stale queries, preserves endpoint identity, handles connected and out-of-scope routes explicitly, reports path-local evidence, synchronizes URL/view state, and keeps selected path details aligned with the graph.
- **NODE-01 through NODE-17: fixed.** Full correlation scope retains the selected resource and exposes truncation; zoom changes event clustering and logical histogram resolution while DOM bins remain windowed; remote member links load their own plug-in snapshot; historical dependencies, duplicate tree instances, range semantics, source-lane fairness, stale-response guards, revision-scoped dashboards, hover alignment, depth disclosure, keyboard handling, and lane counts were corrected.
- **Automated verification:** 138 tests passed with one expected Windows symlink-privilege skip. JavaScript syntax checks passed for both `app.js` and `topology.js`.
- **Route/API replay:** all six A/P1/B node-order permutations, all 389 post-fix route-table actions, all advertised routing contexts, and all 14 route scenarios executed successfully. Recursive-static and same-node connected-external scenarios now complete without stale results.
- **Browser replay:** range brushing grouped only in-range records at the top of the virtualized log; Escape cleared the selection; 1x to 10x changed visible event glyphs from 16 clusters/18 individual marks to 2 clusters/208 marks; 1000x produced 180,000 logical density bins but only 324 DOM bins; Show-all retained the selected ETG and reported the 500-node cap; historical expansion produced eight relationship-specific child rows and could collapse/re-expand; PE-B opened a PE-B-only plug-in snapshot; stale-FIB paths reported 0 active and 2 unusable; selected P2 path details matched the P2 graph.
- Browser console logs were empty on the full topology page, two-node subset page, 125K node workspace, and PE-B member workspace.
