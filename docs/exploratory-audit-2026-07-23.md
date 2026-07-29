# Exploratory audit ledger — 2026-07-23

> **Historical snapshot.** This ledger preserves the findings, decisions,
> validation counts, measurements, and localhost URLs of the audited
> 2026-07-23 revision. Its “fix in this audit,” “recorded,” “remain,” and
> similar status language is not a current backlog. Use the
> [README](../README.md) and [demo guide](../demo/README.md) for current
> commands, and use the [architecture](architecture.md),
> [plug-in contract](plugin-contract.md), and executable tests/CI for current
> behavior and ownership.

Scope: the split frontend/backend demo at `http://127.0.0.1:8765`, including
the multi-node topology and route workbench, the 125K-event node workspace, and
their HTTP contracts.

Status meanings:

- `fix in this audit` — a bounded browser/API correctness fix, with focused
  regression coverage, belongs in the current repair pass.
- `recorded` — a larger contract or migration decision is documented here and
  must not be implemented by adding device-specific guesses to the core.

Ownership rule: the core owns validation, time selection, budgets, paging,
async consistency, and generic rendering. Node plug-ins own device vocabulary,
normalized resource/route/status meaning, and presentation descriptors.
Federation/linker plug-ins own cross-node matching and inferred connectivity.

## Patch ledger

| ID | Severity | Reproduction / evidence | Core-versus-plug-in ownership | Status |
| --- | --- | --- | --- | --- |
| EA-01 | High | Start with all 9 devices selected, click **Clear selection**, and observe 0 checked devices plus `members=` in the URL while the old 16-node topology remains visible. An empty pending selection must show an explicit empty state, not the last applied graph as current data. | Core browser state: separate edited, pending, and applied node selections and invalidate stale graph/metrics. | fix in this audit |
| EA-02 | High | Trace `all-active-ecmp` in both directions, choose **All paths**, then switch Forward/Return. `#mn-route-path-tabs` retains labels from the prior direction until a graph path is selected. | Core browser state: path index, selected path, graph, and detail panel must all derive from the active directional trace. Plug-ins continue to supply candidate paths. | fix in this audit |
| EA-03 | High | In node-a's route table choose **Use in trace** on the `srv6_policy` row. The seed banner identifies `2001:db8:2::/128`, but the form is replaced with `10.255.0.2/32`; tracing then returns no candidate. | Boundary: the plug-in owns the row's exact `trace_query`; the core must preserve that advertised source/destination identity without substituting a display or next-hop value. | fix in this audit |
| EA-04 | High | Click **Use in trace** and do not trace. The row is immediately styled as “used by focused trace,” because the seed ID is mixed into response matches. | Core browser state: represent a seed as pending input; only returned path-local route-entry references are matches. | fix in this audit |
| EA-05 | Medium | Seed a route-table row, then edit Source, Destination, or VRF. The old **Seeded from route table** banner remains even though the form no longer represents that row. | Core browser state: editing any seed-owned field clears the seed and rerenders both the banner and route table. | fix in this audit |
| EA-06 | High | Seed the node-c asymmetric backup row, trace, then select the shorter `via-transit-p-2` path. The original backup row remains highlighted although the selected path references only its own node-c and transit-p-2 rows. | Core browser correlation: selected-path references are authoritative; the seed is only a pre-trace/fallback reference. Plug-ins provide exact row references. | fix in this audit |
| EA-07 | High | Reconstruct at absolute UTC ns `1759680622051000000`. The API returns 2 degraded network segments and 2 unusable inter-node links, but degraded values fall through to healthy styling and attention counts. | Core browser maps only canonical `usable/degraded/unusable/unknown` values; the producing plug-in/linker owns the normalized value. | fix in this audit |
| EA-08 | High | At the same failure time, node-a and transit-p-1 previews contain down/unusable resources, yet both device cards remain green and **Highlight attention** finds none. | Boundary: core may conservatively aggregate explicit normalized preview classes for this demo, but may not infer health from vendor text. The authoritative node-health contract remains DF-02. | fix in this audit |
| EA-09 | Medium | The route-table filter labelled **Address family** contains `vpnv4_unicast`, `mpls_labeled_unicast`, and `l2vpn_evpn`, while rows separately expose `ipv4`, `mpls`, and `l2vpn` address families. | Core presentation: label/filter the transported `route_family` field as **Route family**; plug-ins own the available family values. | fix in this audit |
| EA-10 | Medium | With no VPN profile selected, the browser recommends one by matching `/evpn/i` against a profile ID/label. A renamed or unrelated profile containing “EVPN” is therefore selected without a declared semantic role. | Plug-in supplies an exact `projection_role`; core performs exact role matching and otherwise shows no semantic suggestion. | fix in this audit |
| EA-11 | Medium | Two advertised endpoints can share a visible value such as `203.0.113.0/24`. The datalist/display fallback can emit the same string for both, so the intended endpoint is ambiguous or resolves to the first match. | Core identity/presentation: append the stable source/destination ID whenever preferred labels collide; plug-ins own IDs and labels. | fix in this audit |
| EA-12 | High | Live ETG bundle query: 2,500 matches, 100 returned, `next_offset=100`. Live ETE query: 3,500 matches, 500 returned, `next_offset=500`. The resource-table UI neither submits `offset` nor consumes `next_offset`, so most resources are unreachable. | Core browser/API mechanics: page or progressively virtualize results while preserving plug-in-declared columns, grouping, and row actions. | fix in this audit |
| EA-13 | High | Query correlation for `control-plane/IP_ROUTING/blue` at depth 3 and `max_nodes=500`: 500 nodes, 499 edges, `truncated=true`. The layout allocates about 122 px per row (roughly 61,000 px), while relationship lists silently render `slice(0, 30)` but display the full count. | Core renderer/query UX: use a bounded scroll/aggregation viewport and disclose “30 of 499” plus server truncation. Relationship semantics remain plug-in-owned. | fix in this audit |
| EA-14 | High | A live relationship-history expansion returned 100 lanes, 1,082 intervals, and `relationship_history_expansion.truncated=true`. Timeline normalization ignores that metadata, so omitted dependent lanes are undisclosed. | Core API/browser mechanics: retain expansion totals/dropped IDs and render an omitted-results node or refine/load-more affordance. | fix in this audit |
| EA-15 | High | Select a time range that contains only some points in a collapsed event/source cluster. Initial rendering checks point times, but later range updates intersect the cluster's min/max envelope as if it were a status interval, producing gap false positives, boundary false negatives, and no partial state. | Core temporal renderer: recompute cluster membership from contained point timestamps; interval intersection is reserved for actual intervals. | fix in this audit |
| EA-16 | Medium | Open a plug-in dashboard whose result is not cached, or cold-load a page with default-open modules. The module can render before `dashboardPending` is set and briefly report “The authoritative point-in-time table was not returned” before the request starts. | Core async UI: enter pending state before rendering/requesting so the first frame is a loading state. Plug-ins still own dashboard descriptors and data. | fix in this audit |
| EA-17 | Medium | Enter an extreme finite zoom such as `1e308`. Input validation accepts it, derived pixel/bin multiplication becomes `Infinity`, and density code reaches `BigInt(Infinity)`. | Core renderer: retain logically unbounded zoom but use a windowed transform and validate/saturate derived numeric values before Number-to-BigInt conversion. | fix in this audit |
| EA-18 | High | `/api/node-demo/node-a?basis_kind=absolute_time` without `time_ns` silently falls back to another basis; supplying `time_ns` with `basis_kind=relative_to_watermark`, or an offset with an absolute basis, is similarly contradictory but can be coerced by branch order. | Core API validation: require one coherent discriminated basis and reject missing/conflicting selector fields with 422. Plug-ins receive only the resolved basis. | fix in this audit |
| EA-19 | High | Explicit `null`/boolean/float integer fields and wrong JSON shapes (for example `time_ns:null`, `max_nodes:1.5`, or string `record_lane_rules`) previously reached `int(...)`/iteration paths and produced coercion or HTTP 500. | Core trust boundary: strict integer-or-decimal-string and container-shape validation with stable 422 responses; no plug-in semantics are involved. | fix in this audit |
| EA-20 | High | Create an absolute, strict topology context for node-a, then query route tables with that `topology_context_id` plus a relative basis and `best_effort`. Cached context lookup must reject the contradiction; it must not echo or reuse data from another time/node/filter scope. | Core cache/API: bind contexts and cursors to canonical basis, clock policy, selected members, projections, perspectives, and filters; reject scope disagreement. | fix in this audit |
| EA-21 | High | After enforcing the strict cached-context contract, cold-load the topology page. The route-table request supplies both qualified `node_queries` and redundant `node_ids`, receives 422, and leaves every route table unavailable. | Core frontend/API integration: send exactly one node-scope selector. Prefer the qualified per-member plug-in queries and use bare IDs only as a compatibility fallback. | fix in this audit |
| EA-22 | High | Cold-load `/node` after the point-cluster range repair. Initial timeline rendering fails with `Cannot access 'bounds' before initialization` because the cluster renderer reads the local range bounds before their declaration. | Core temporal renderer: initialize shared range state before rendering lifecycle, status, event, and source-record glyphs. | fix in this audit |
| EA-23 | High | Expand the selected IP-routing relationship history. A 100-lane bounded response becomes 1,221 DOM rows because each time interval for the same parent/type/child identity creates another tree child. | Core temporal renderer: group time intervals into one relationship identity/lane and render them as changing ribbons. Plug-ins continue to own relationship type and interval evidence; duplicates remain valid under genuinely different parents. | fix in this audit |

## Recorded contract and migration follow-ups

| ID | Severity | Reproduction / evidence | Core-versus-plug-in ownership | Status |
| --- | --- | --- | --- | --- |
| DF-01 | High | Changing the generic Status perspective control can leave every per-node query unchanged because a profile's `perspective_by_member` mapping overrides it. The control therefore appears effective while being profile-fixed. | Node plug-ins declare local perspective IDs and semantic roles; core needs an explicit generic-role-to-qualified-member-perspective mapping, or must disable a profile-fixed control. | recorded |
| DF-02 | High | Device health currently has to be approximated from partial resource previews; absence of preview evidence can otherwise become green, while a bounded preview cannot prove whole-node health. | Node plug-ins emit normalized local health/completeness; federation may aggregate assembly health under a declared policy; core only validates and renders exact classes. | recorded |
| DF-03 | High | Relative reconstruction resolves different nodes at different local times, and absolute reconstruction carries per-node uncertainty. A single scalar timestamp cannot represent this as a simultaneous world. | Core owns a typed capture-vector basis with per-node resolved time/range, clock domain, uncertainty, and `simultaneity:not_implied`; plug-ins supply clocks/observations and linkers consume the frozen vector. | recorded |
| DF-04 | Medium | Retained records without a usable timestamp are intentionally unplaced by the backend, while browser fallback has historically coerced missing time to the timeline start and made the record range-selectable. | Core retains nullable time, reports `unplaced_count`, and excludes unplaced records from temporal lanes/ranges. Plug-ins may supply timestamp evidence but do not invent core placement. | recorded |
| DF-05 | Medium | The demo exposes overlapping compatibility aliases and free-form legacy/precomputed route endpoints alongside the newer context-bound topology/route APIs. Their lifecycle and authority are unclear to external consumers. | Core needs a versioned deprecation/inventory plan and typed replacements. Demo/plug-in fixtures may remain adapters, but production callers must not depend on their private dictionaries. | recorded |
| DF-06 | High | Many request bodies are `dict[str, Any]`, so generated OpenAPI describes a free-form object rather than integer-string precision rules, basis unions, bounds, cursor scope, or response completeness. | Core API owns Pydantic request/result models and reusable OpenAPI components; plug-in extension fields remain bounded typed extension envelopes. | recorded |
| DF-07 | Medium | Regex-lane validation is implemented in both Python and JavaScript; without one declared dialect, accepted syntax, anchoring, escaping, and work bounds can drift. | Core defines and enforces one bounded regex subset and publishes its limits/capability schema; plug-ins only supply presets within that subset. | recorded |

The immediate fixes must remain vocabulary-neutral: no router acronym, resource
kind, vendor status token, route prose, or profile label may become a new core
branch. Unknown plug-in semantics remain `unknown` and visible.

## Final validation

All `EA-01` through `EA-23` were fixed and replayed against the restarted
125,000-event / 10,000-resource demo. The seven `DF-*` entries remain explicit
contract or migration work rather than device-specific guesses in the core.

- Full regression suite: **313 run: 311 passed and 2 platform-only symbolic-link tests skipped**.
- Split frontend check: **3 routes and 2 JavaScript entry points valid**.
- Strict API probes: missing absolute time, a relative basis with `time_ns`, and
  fractional `max_nodes` each return **422**.
- Topology replay: clearing all devices yields zero graph nodes and an explicit
  empty state; degraded/unusable evidence receives warning/error styling.
- Route replay: the strict context loads **389** route rows across 9 node
  tables, bidirectional ECMP returns both candidates, direction changes replace
  the candidate index, and the SRv6 row seeds `2001:db8:2::/128` as pending
  input rather than falsely marking it as a traced match.
- Node replay: ETG paging advances from `1–100` to `101–200` of 2,500; ETE
  exposes `1–500` of 3,500; the high-degree graph shows 31 of 500 resources
  with a pageable 499-relationship index; relationship history discloses its
  server bound and renders 152 rows instead of 1,221 duplicated rows.
- Temporal replay: `+230 s` through `+250 s` reports and groups exactly 10,001
  events first, individual point highlights stay within the range, partial
  clusters remain partial, and extreme unrepresentable zoom is rejected without
  introducing a product-level zoom ceiling.
