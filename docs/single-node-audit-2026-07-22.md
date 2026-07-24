# Single-node workspace audit — 2026-07-22

Scope: the full-scale single-node workspace at `http://127.0.0.1:8765/node`,
its revision APIs, and the scale plug-in fixture. The exploratory pass was
completed before any implementation changes were made.

The ownership rule used throughout this audit is:

- **Core** owns temporal evaluation, bounds, pagination, async request
  consistency, generic rendering, redaction enforcement, workspace isolation,
  accessibility, and API validation.
- **Plug-ins** own resource and relationship vocabulary, canonical identifiers,
  typed keys, searchable/presented fields, normalized outcomes/status classes,
  route/topology semantics, icons, dashboards, lane presets, and explanatory
  text.
- **Boundary** findings require a plug-in declaration plus generic core
  enforcement or rendering; the core must not infer device semantics.

## Confirmed defects

### B01 — Temporal resource search evaluates static catalog state

- Severity: high
- Owner: core, guided by plug-in property descriptors
- Reproduction: at `1759680400000000000`, neighbor `peer-00000` is
  `down/unreachable`, but flat `NEIGHBOR` search and the
  `interface-neighbor-bundles` search for `unreachable` return zero matches.
- Cause: the query applies search to the catalog record before evaluating the
  resource envelope at `time_ns`.
- Required fix: search the point-in-time key/state envelope and honor plug-in
  `searchable` and `sensitive` declarations.

### B02 — Selected scale events omit available detail

- Severity: high
- Owner: core UI; plug-in supplies the normalized event/effect payload
- Reproduction: selecting `scale-event-00001403` shows `{}` for Properties and
  Result, `unknown` quality, and no affected-resource detail. The existing
  event-detail endpoint returns service, encapsulation, result, three affected
  resources, and their exact effects.
- Required fix: load event detail on demand, cache it, and render generic
  affected-resource/effect information without embedding ETG/ETE/DTE logic.

### B03 — Per-resource timeline marks lose their exact effect

- Severity: high
- Owner: boundary
- Reproduction: one scale event can create ETG, ETE, DTE, Virtual Interface,
  and Neighbor with different resulting conditions. Timeline marks retain only
  `effect_type/state_changed`, so a neighbor-lane mark can display the primary
  event's generic `Create` instead of neighbor `up`.
- Required fix: carry the matched `ResourceEffect` envelope on each mark. The
  plug-in owns the effect state fields and condition descriptor; the core uses
  the matched effect for hover and inspector status.

### B04 — Reset leaves the old selected-period event-log grouping

- Severity: high
- Owner: core UI
- Reproduction: select `+1.402 s .. +1.964 s`, then press Reset. The range band
  and Clear button disappear, but the log still begins with `SELECTED PERIOD
  +1.402 s to +1.964 s`.
- Required fix: rebuild the event-log model and clear range classes on Reset,
  matching Escape and Clear Range.

### B05 — Half-open temporal boundaries are highlighted as overlapping

- Severity: high
- Owner: core UI and core range summary
- Reproduction: select `[+120.500 s, +121.000 s]`. A status segment ending
  exactly at `+120.500 s` receives `in-range`.
- Cause: post-render highlighting and local range summary use `end >= start`,
  overriding the half-open helper.
- Required fix: use half-open interval intersection consistently for status,
  lifecycle, relationship, and summary evaluation. Point events remain
  inclusive.

### B06 — Resource rows are briefly labelled with a newer time than their data

- Severity: high
- Owner: core UI
- Reproduction: moving the cursor immediately rerenders the previous
  `resourceQuery` while the summary prints the new cursor time. The correlation
  panel already has a correct pending/shown-time state; resources and dashboards
  do not.
- Required fix: track requested and returned resource times, mark the view
  pending/stale, and never attribute old rows to the requested time.

### B07 — “Show all correlations” remains rooted at the selected resource

- Severity: high
- Owner: core UI
- Reproduction: select a resource outside its lifecycle, then choose Show all.
  The request still sends `resource_ids=[selectedResourceId]`, so it remains
  empty although other active resources exist.
- Required fix: full mode sends no root filter; the selected ID is only a client
  highlight.

### B08 — Correlation root input bypasses `max_nodes`

- Severity: high
- Owner: core API
- Reproduction: 600 ETG roots, `depth=0`, `max_nodes=10` returns 600 nodes and
  `truncated=false`.
- Required fix: deduplicate and cap roots before traversal, with requested,
  accepted, inactive/unknown, and dropped metadata.

### B09 — Timeline response bounds are not enforced

- Severity: high
- Owner: core API
- Reproduction: a one-resource request with `max_glyphs=1` returns 66 raw marks;
  `viewport_pixels` is ignored. Cluster hover then silently truncates to 40 and
  there is no documented drill-down endpoint.
- Required fix: deterministic aggregation/bounding and paged cluster detail.

### B10 — Range endpoint diffs share the status-segment budget

- Severity: high
- Owner: core API
- Reproduction: the whole range affects 10,000 resources but returns only 14
  endpoint diffs; `EVPN_ES/es-00100` is omitted despite changing absent→active.
- Required fix: independent bounded collectors and independent exact/truncated
  counts for endpoint diffs, status segments, events, and relationships.

### B11 — Relationship-history expansion silently drops all dependent lanes

- Severity: high
- Owner: core API
- Reproduction: 100 roots report 445 expanded IDs, but the 100 returned lanes
  are all roots and no relationship intervals are returned.
- Required fix: reserve capacity for accepted children and return explicit
  expansion truncation/dropped-ID metadata.

### B12 — Route resolution has an async overwrite race

- Severity: high
- Owner: core UI
- Reproduction: `resolveRoute()` has no request generation. A slower older
  request can overwrite a newer basis selection and the result has no reliable
  requested/shown time state.
- Required fix: generation guard plus pending/requested/returned basis labels.

### B13 — Deep-linked node snapshots can query unrelated scale data

- Severity: critical
- Owner: core workspace isolation and boundary
- Reproduction: `/api/node-demo/node-a` advertises zero events, but its range
  selection posts to the global scale revision and returns 999 unrelated scale
  events. The fixed route resolver similarly returns global review/scale data.
- Required fix: node-scoped context/endpoints or disable the capability unless
  the member plug-in supplies it.

### B14 — Scale route and underlay projections reference absent resources

- Severity: high
- Owner: scale plug-in fixture; core validates references/availability
- Reproduction: single-node route output references `EVPN_ROUTE`,
  `FORWARDING_GROUP`, `etg-evpn-east`, and `ete-srv6-p2`; none exists in the
  loaded 10K catalog. Underlay status sources reference old `pe-a/p1/p2`
  resources, producing static unknown links mixed with scale relationships.
- Required fix: scale-owned route/topology data must reference its own catalog
  or omit the capability; the core marks invalid projections unavailable.

### B15 — Virtual Interface history starts in final all-active state

- Severity: high
- Owner: scale plug-in fixture
- Reproduction: at the first single-home event, ETG0 is `single-home`, while
  `ae-00000` already reports `all-active` and `neighbor_count=2`; only one
  neighbor relationship exists then.
- Required fix: initial VIF state is single-home with the time-valid count, then
  plug-in events modify it when multihoming and the extra neighbor appear.

### B16 — Invalid zoom text can disagree with rendered zoom

- Severity: medium
- Owner: core UI
- Reproduction: render at zoom 4, enter `0.5`. The input displays `0.5`, but the
  timeline remains at zoom 4 because the handler silently returns.
- Required fix: clamp/normalize the displayed control value to actual state and
  expose validation feedback without adding an upper scale limit.

### B17 — `GET resources/at?time_ns=0` substitutes capture time

- Severity: medium
- Owner: core API
- Reproduction: GET with `time_ns=0` returns capture state; POST resource query
  honors zero.
- Required fix: distinguish `None` from numeric zero.

### B18 — Invalid JSON shapes and null timestamps produce HTTP 500

- Severity: medium
- Owner: core API
- Reproduction: explicit `null` timestamps in resource, timeline, range, and
  correlation requests return 500; a string `record_lane_rules` also returns
  500.
- Required fix: validate shapes and return stable 4xx responses.

### B19 — Generic dashboard aggregates depend on a bounded current page

- Severity: high
- Owner: core API/contract
- Reproduction: at `+0.000 s`, Forwarding population claims point-in-time
  statistics for the complete catalog while its table contains three fallback
  timeline resources. Switching resource tabs/searches changes the input set.
- Required fix: descriptor-driven aggregates and tables query the authoritative
  point-in-time population. Plug-ins only declare filters/columns/aggregations.

### B20 — The incident chain invents causality

- Severity: high
- Owner: boundary
- Reproduction: the first three failed events are drawn with arrows without
  consulting causal links.
- Required fix: render a chain only from plug-in-emitted causal links; otherwise
  present an unordered “Highlighted failures” list.

### B21 — Sensitive/searchable plug-in property rules are not enforced

- Severity: critical for production
- Owner: boundary
- Reproduction: generic hovers, tables, topology previews, and local search dump
  state without consulting `PropertyDescriptor.sensitive/searchable`.
- Required fix: central generic field projection/redaction enforced by core.

### B22 — Core guesses device-specific failure/status semantics

- Severity: high
- Owner: boundary
- Reproduction: `eventFailed()` interprets arbitrary `*status`; status styling
  uses text regexes; event mark class guesses create/delete from action strings;
  relationship labels are raw IDs title-cased.
- Required fix: plug-ins normalize outcome/effect/status class and relationship
  presentation; core consumes the normalized contract and falls back to
  `unknown`, not a semantic guess.

### B23 — Typed/compound key fallbacks can collide

- Severity: high
- Owner: core contract
- Reproduction: nested typed values pass through `String(value)` and can become
  `[object Object]`; fallback layer/kind parsing assumes slash-delimited IDs even
  though canonical IDs are opaque.
- Required fix: require/preserve canonical resource IDs and deterministic typed
  key formatting; do not derive device semantics from ID text.

### B24 — Bundle traversal/deduplication is not safely bounded

- Severity: high
- Owner: core API
- Reproduction: child limits are applied after recursive child construction;
  parallel relationships can collapse because dedupe keys omit relationship ID.
- Required fix: bound before recursion and use stable relationship identity.

### B25 — A zero-result search can discard the selected resource kind

- Severity: medium
- Owner: core UI
- Reproduction: select the Neighbor table, search for a value that has no
  matches, then clear the search. The zero-result response has no kind counts,
  so the client clears `selectedResourceKind`; the recovery request becomes an
  unfiltered mixed-kind page and can render `0 shown of 2,500` for a kind whose
  rows were not present in that bounded page.
- Required fix: preserve the selected kind while a non-empty search has no
  matches, so clearing the search re-queries the same plug-in resource kind.

## Implementation outcome

All 25 confirmed defects have an implementation fix. “Fixed” below means the
code path has focused automated coverage and was included in the final suite;
the interaction-sensitive paths were also repeated against the live server.

| ID | Status | Ownership preserved in the fix |
| --- | --- | --- |
| B01 | Fixed | Core searches the point-in-time envelope and enforces plug-in `searchable`/`sensitive` descriptors. |
| B02 | Fixed | Core hydrates and caches selected-event detail; the plug-in remains the author of normalized properties, result, and effects. |
| B03 | Fixed | Core binds each mark to the exact resource effect; effect vocabulary and condition fields remain plug-in declarations. |
| B04 | Fixed | Core Reset/Escape/Clear rebuild the log and clear selected-range classes together. |
| B05 | Fixed | Core range rendering and summaries now use half-open interval intersection; point events retain instant semantics. |
| B06 | Fixed | Core resource and dashboard views expose pending plus requested/returned time and reject stale async responses. |
| B07 | Fixed | Core “show all” omits the root filter and treats selection only as a highlight. |
| B08 | Fixed | Core deduplicates and bounds roots before traversal and reports accepted, inactive/unknown, and dropped roots. |
| B09 | Fixed | Core derives deterministic viewport/glyph bounds, returns bounded previews, and provides paged exact cluster detail; the client hydrates and scrolls those pages. |
| B10 | Fixed | Core uses independent collectors, limits, totals, and truncation metadata for events, status, endpoint diffs, and relationships. |
| B11 | Fixed | Core reserves lane capacity for accepted children and discloses expansion truncation/dropped IDs. |
| B12 | Fixed | Core route UI uses request generations and requested/returned basis labels. |
| B13 | Fixed | Core snapshot workspaces stop at node-local capabilities/data and do not fall through to the global revision. |
| B14 | Fixed | The scale plug-in no longer advertises stale route/underlay projections; core capability checks keep unavailable projections unavailable. |
| B15 | Fixed | The scale plug-in now emits time-valid single-home, neighbor-count, and all-active VIF transitions. |
| B16 | Fixed | Core normalizes invalid zoom input to rendered state without imposing an upper zoom cap. |
| B17 | Fixed | Core distinguishes an omitted time from numeric zero. |
| B18 | Fixed | Core request parsing rejects null/wrong-shaped inputs with stable 422 responses. |
| B19 | Fixed | Core evaluates safe declarative dashboards over the authoritative temporal population; plug-ins own filters, columns, sorting, and aggregates. |
| B20 | Fixed | Core draws causal arrows only for explicit plug-in links; unlinked failures remain an unordered list. |
| B21 | Fixed | Core applies central descriptor-driven search projection and redaction to resources, states, events, effects, tables, and previews. |
| B22 | Fixed | Core consumes normalized outcome/effect/condition classes and relationship presentation, falling back to neutral unknown; plug-ins own device semantics. |
| B23 | Fixed | Core preserves opaque canonical IDs and deterministically renders typed values; plug-ins own typed/compound key construction. |
| B24 | Fixed | Core bounds before recursive expansion and deduplicates by stable relationship identity. |
| B25 | Fixed | Core preserves the selected plug-in resource kind through a zero-result search and re-queries that kind when the search is cleared. |

Focused coverage includes API bounds/validation, temporal boundaries, dashboard
evaluation, property policy/redaction, normalized condition contracts, semantic
identity boundaries, snapshot isolation, async UI guards, and cluster-detail
pagination. The rebuilt packed fixture validates at 125,000 matching events,
10,000 resources, and generator version 7.

## Potential improvements

These are recorded separately from correctness fixes so they do not silently
expand core semantics.

1. Completed: the 125K-event bootstrap is now server-windowed, with paged
   normalized-log loading and indexed visible-window density queries. Core
   responsibility.
2. Add complete pagination controls to generic and bundled resource tables;
   current API pages are not exposed by the UI. Core responsibility.
3. Make flat resource tables use the same descriptor-driven icon, hover, and
   details projection as bundled tables. Boundary responsibility.
4. Render typed key wrappers as a readable type/value pair instead of raw JSON.
   Core presentation; plug-in owns the type/value.
5. Separate singular row labels from plural/index display names. Boundary.
6. Replace fixed three-row combined-correlation packing with interval collision
   packing and bounded overflow. Core renderer.
7. Use pixel-derived minimum interval widths and viewport-windowed ruler ticks
   at high zoom. Core renderer.
8. Normalize histogram heights against a resolution-level maximum so horizontal
   scrolling does not change apparent density. Core renderer.
9. Preserve logically unbounded zoom through a windowed coordinate transform,
   rather than unbounded CSS element width. Core renderer.
10. Expose visible stale/fallback/coverage state when graph or timeline API
    requests fail; never make a lane-limited fallback look authoritative. Core.
11. Complete ARIA tabs, drawer focus return/trap, lane-picker focus return, and
    mobile navigation. Core accessibility.
12. Replace fixed inline lane widths with a shared responsive CSS variable and
    preserve touch `pan-y` until a horizontal brush is recognized. Core UX.
13. Expand the single-node route form from plug-in-declared query fields
    (source, destination, VRF, family, labels/SIDs, and extensions). Boundary.
14. Add neighbor health, protocol, and reachability dashboards/lane presets and
    include Neighbor in the default scale review. Scale plug-in.
15. Add real cross-layer lag/failure inconsistencies and ground-truth rules to
    the scale consistency report. Scale plug-in.
16. Replace stale review prompts that mention absent Forwarding Group/Glue
    resources with scale-plug-in prompts. Scale plug-in.
17. Preserve relationship provenance/cause-event fields in bundled rows and
    let plug-ins declare explanatory relationship presentation. Boundary.
18. Distinguish inactive, unknown, dropped, and absent correlation roots in API
    responses. Core contract.
19. Add point-in-time `existing_count/absent_count` and plug-in defaults for
    including absent catalog resources. Boundary.
20. Upgrade topology-member plug-in snapshots to carry full kind descriptors,
    views, dashboards, and icons. Member plug-ins plus generic adapter.

## Scale fixture implementation follow-up

- B14 fixed in generator version 7: the full-scale loader no longer inherits
  route resolutions or static underlay status sources from the unrelated review
  projection. The scale plug-in explicitly declares route resolution and
  underlay topology unavailable while retaining its catalog-valid generic
  resource-association topology.
- B15 fixed in generator version 7: Virtual Interface keys are stable
  `vrf + interface_name` keys; create effects are single-home with the count
  valid at that event; a later neighbor discovery modifies the count; and the
  first Ethernet Segment attachment modifies the VIF to all-active at the same
  timestamp as its `uses_interface` relationship.
- Improvement 14 is covered by a default-open Neighbor health dashboard, a
  Neighbor/adjacency source-record lane preset, a Neighbor in the initial scale
  review set, and protocol/reachability metrics. These declarations remain
  plug-in data consumed by generic dashboard, table, lane, and timeline code.
- Improvement 15 is only partially covered: the scale plug-in now declares and
  reports its Neighbor restore/reachability rule. A genuinely lagging or failed
  cross-layer update with a failing/unknown result is still future fixture work.
- Improvement 16 is covered: scale-specific review prompts replace the stale
  Forwarding Group and Glue questions.
- Improvement 4 is covered by the core's deterministic type/value rendering;
  plug-ins still own the typed atom and compound-key schema.
- Improvement 18 is covered by the bounded correlation-root classification
  returned by the core API.
- Improvement 17 is partial: plug-ins now declare relationship label and
  direction presentation, but complete relationship provenance/cause-event
  display in every bundled row remains future work.
- Improvement 1 is now covered by the server-windowed scale bootstrap, visible
  density queries, and sparse virtual event log. Improvements 2–3, 5–13, 19,
  and 20 remain future work. They are layout, accessibility, projection, and
  richer member-snapshot improvements, not unresolved correctness defects
  B01–B25.

The 125K-event/10K-resource archive was rebuilt and validated at generator
version 7. Both launch scripts now reject older packed fixtures and regenerate
them when necessary.

## Scale history optimization follow-up

- The scale bootstrap fell from about 67.8 MB to 1.29 MB uncompressed and from
  about 2.14 MB to 72 KB compressed. It carries the compact resource catalog
  and history transport contract, not 125,000 event objects or 5,000 source
  records.
- The core now owns exact paging, selected-range-first grouping, stable locate,
  redaction-before-search, and indexed density binning. The scale plug-in still
  owns event/resource/source vocabularies, labels, presentation, and the opaque
  source stream grouping used by the generic history controls.
- The normalized event log uses a sparse virtual scroller with bounded page
  caches; timeline density fetches only the visible/overscan window and changes
  logical resolution with the unbounded timeline zoom scale.
- Direct indexed queries returned a 120-row log page in under 1 ms and full
  180–240-bin density responses in under 1 ms on the validation machine. A
  4,096-bin density query remained under 10 ms.
- The follow-up search optimization builds the exact redacted, case-folded
  event corpus once and retains bounded compact result postings. The initial
  in-memory implementation reduced warmed direct searches to 28–34 ms and
  later pages to under 1 ms, but increased the warmed server working set to
  about 607 MB.
- The next optimization persists the same safe corpus in an immutable SQLite
  sidecar keyed by the archive SHA-256, projection ABI, Python cache tag, and
  Unicode case-folding version. The first build produced a 219,140,096-byte
  sidecar and became ready about 3.5 seconds after the server first reported
  healthy. A restart reused it immediately: full-scale health with all 125,000
  search documents ready took about 3.18 seconds, with no corpus rebuild.
- The persistent version reduced the warmed server working set to about 429 MB
  and private memory to about 417 MB. First unseen HTTP searches took roughly
  0.32–0.71 seconds and repeated virtual pages took 5–24 ms including
  PowerShell/HTTP overhead, versus about 3.4 seconds in the original path.
  Focused security coverage verifies that declared sensitive event values are
  absent from both search results and the SQLite file.
- The next serving layer adds an external-content FTS5 trigram candidate index while
  retaining the ordinary safe-text table and exact `instr` verification. On the
  actual 125,000-document corpus it increased the sidecar from 219,140,096 to
  277,897,216 bytes. A cold source-checked build became search-ready about
  32.5 seconds after process start while the web server remained available;
  direct reopen validation of the completed sidecar took about 1.27 seconds.
  Live HTTP checks measured about 30 ms for a rare match, 7.5 ms for no match,
  41 ms for a punctuation-heavy withdrawal query, and 142 ms for a broad
  colon-heavy key. One/two-character and corpus-wide searches deliberately
  retain exact scans at about 265–384 ms. Builds without FTS5 persist and reuse
  a scan-only sidecar with identical results.
- Four superseded development sidecars were removed after v5 validation,
  reclaiming 1,055,174,656 bytes; the active v5 cache is the only remaining
  history-search sidecar.
- Browser validation covered a deep jump near event 118,000, a 43,750-event
  selected range with exact inside/outside grouping, 1×/8×/100× density zoom,
  CTF plus external-source streams, timeline-to-log and log-to-timeline jumps,
  and authoritative cursor updates. The browser console stayed clean.

## Behaviors validated during the exploratory pass

- Range-selected normalized events are grouped at the top and marked
  `range-included`.
- Neighbor state changes exactly at ES withdrawal and restoration.
- DTE next-hop state matches time-valid next-hop correlations across failover,
  restore, and churn.
- Correlation view updates to the selected moment and excludes resources before
  lifecycle creation.
- Interface-neighbor and ETG-path bundle expansion/collapse works.
- Timeline layers, custom resource search, selected+correlated lane preset, and
  combined/separate relationship presentations work.
- Zoom 1→4→100 changes timeline width and histogram resolution together.
- Dashboard open/close, collapse/expand, and move controls work.
- Alternate temporal-topology projection/perspective/time-basis/clock-policy
  combinations execute without client errors.
- Source-record paging, regex lane mark fairness, and topology change cursors
  were verified by the API audit.
- A zero-result temporal Neighbor search now preserves the Neighbor tab and
  restores all 500 rows when the search is cleared.

## Final validation

- `node --check` passed for the final `app.js`; Python compilation and
  `git diff --check` also passed. The generated-fixture ACL warnings emitted by
  sandboxed Git inspection are a Windows identity artifact, not missing files.
- The complete suite passed **262 tests** with two expected skips: creating
  symbolic links without the Windows privilege required by those safety tests.
- `router-state-lab-100k.tgz` passed archive validation with 125,000 matching
  events, 10,000 resources, and generator version 7.
- The Conda demo was restarted on `http://127.0.0.1:8765/node`; `/health`
  reported `full-scale-100k-plus`, 125,000 events, 10,000 resources, and 5,000
  retained source records.
- Live browser checks covered event-detail hydration and per-resource effects;
  paged cluster hydration; horizontal range selection, selected-period log
  grouping, and Escape clearing; temporal Neighbor search across withdraw and
  restore; correlation changes at multiple moments; full-graph recovery from an
  inactive selected root; lane plus density zoom (1×, 2.5×, and 8×); dashboard
  collapse/expand/reorder and authoritative population labels; mixed normalized,
  CTF, and external virtualized logs; node-snapshot isolation; correlation
  collapse/expand and the persistent back-to-top control.
- The final main workspace showed no visible alerts or toast errors. A live
  dashboard query evaluated 9,500 relevant temporal resources in about 964 ms;
  cluster paging and unrooted graph queries returned their declared totals and
  bounds.
