# Focused graph warning: query scope investigation

Audited source: `112d346`, 2026-10-21. This supplemental investigation does not
establish missing focused data or add a unique bug to the main findings count.

## Browser observation supplied by the primary auditor

On the existing 1M demo, the primary auditor reported that focused ETG1874 showed
**3 resources and 3 relationships**, together with:

> Server result capped at 500 resources; refine or focus to inspect omitted relationships.

The corresponding ETG0 view did not show this warning. The source-review agent
did not operate the browser or inspect its internal application state. The
service probe below is separate evidence, not execution of a browser case.
The primary auditor repeated the live focused-view observation and saved its
rendered resource identities and caption in
`.runtime/audit-600-2026-10-21/single-node/graph-scope-focused-etg1874.json`.

## Source explanation

- [requestGraph](../../frontend/assets/app.js) (`app.js:6924`) requests depth 3
  for a selected focus, with a 500-node limit. Full-graph mode requests depth 20.
- [scopedGraph](../../frontend/assets/app.js) (`app.js:6819`) reduces focused
  display to edges incident to the selected resource and their endpoints. It
  spreads the original response, retaining its `truncated` flag.
- `renderGraph` applies this scope before the canvas bound (`app.js:7532`), then
  uses the retained flag for the quoted warning (`app.js:7681`).
- The indexed correlation query sets `truncated` when a traversal frontier
  exceeds remaining capacity
  ([revision_queries.py:751–789](../../src/router_dump_analyzer/revision_queries.py)).
  This flag describes the requested neighborhood, not specifically the incident
  edges eventually displayed by the client.
- The generator makes ETG1874's primary ETE point to the shared IP-routing
  resource. ETG0's ETE instead points to ETG1, because its index is divisible by
  four ([`_scale.py:1769`](../../demo/rsl_demo_generator/_scale.py)). Thus the
  shared hub's large neighborhood is encountered at a different traversal depth.

## Production-service probe with generated relationships

The source-review agent executed `RevisionQueryService.correlation` using
`CorrelationQuery(time_ns=1759680719996000000, max_nodes=500)` for ETG0 and
ETG1874 at depths 1, 2, and 3. The fixture used
`rsl_demo_generator._scale._layout(7500)` and `_relationship_lines(1000000,
layout)`, filtering validity intervals at that timestamp. This produced 7,500
endpoint resources and 13,874 active relationships.

`tests.test_single_node_api_bounds.scale_dataset` and
`tests.support.normalized_data.static_data_service` supplied the indexed service
fixture. All endpoint resources were declared present with simple test states.
This preserves generated relationship structure, but does not load the running
archive, its full lifecycle history, node prefixes, or auxiliary resources.

| Focus | Query depth | Service nodes / edges | Service truncated | Incident-scope nodes / edges |
|---|---:|---:|---|---:|
| ETG0 | 1 | 4 / 5 | false | 4 / 4 |
| ETG0 | 2 | 8 / 14 | false | 4 / 4 |
| ETG0 | 3 | 23 / 42 | false | 4 / 4 |
| ETG1874 | 1 | 3 / 3 | false | 3 / 3 |
| ETG1874 | 2 | 5 / 5 | false | 3 / 3 |
| ETG1874 | 3 | 500 / 501 | true | 3 / 3 |

For all six queries, the returned incident edge IDs exactly matched an exhaustive
scan of the generated active relationships incident to the focus. A depth-1
service result can also contain edges between its discovered neighbors, which
explains ETG0's five service edges versus four incident display edges.

The probe supports a **query/display scope mismatch**: a real three-hop cap can
coexist with complete direct-neighbor display. It does not demonstrate a stale
global flag, missing focused edges, or completeness of the live archive result.

## Focused follow-up

Compare a depth-1 query with the existing depth-3 query and an exhaustive direct
relationship reference for the same revision and timestamp. Verify incident
edge identity, not only counts. A focused depth-1 request could avoid querying
hundreds of nodes that the current focused renderer discards. Any change must
retain a truthful truncation warning when the focus itself has more than 499
direct neighbors, and must preserve full-graph behavior and selected-time
validity. Do not suppress every focused warning merely because few nodes render.

No product or skill files changed. The plug-in documentation drift check found
no author-visible API or behavior change requiring maintained authoring updates.
