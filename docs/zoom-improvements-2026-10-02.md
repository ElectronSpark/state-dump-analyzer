# Zoom performance improvements — 2026-10-02

Checkpoint before implementation: `4609c61` (initial loading improvements and
their skill validation). The zoom implementation follows that commit.

- [x] Index narrow timeline windows and next-state-change lookups.
- [x] Aggregate coarse events before projecting details; bound interval details.
- [x] Reuse exact density summaries at multiple resolutions.
- [x] Abort obsolete browser queries and propagate disconnects to core checks.
- [x] Update author/validator skills and run fresh GPT-6.1 Sol usage trials.
- [x] Validate tests, documentation smoke paths, typing and a live browser.

## Behavior and boundaries

Indexed timeline queries keep per-resource timestamp, failure-prefix, interval,
and unique-event union indexes privately on the core data service. Narrow warm
windows use binary searches. Coarse clusters compute exact counts before
redacting bounded previews, preserving selected-event identity and exact
drill-down. Cache entries verify live source identity, use short publication
locks, and have entry and retained-index-unit limits. These limits describe
index units, not measured heap bytes. Cancelled builds publish no partial index.

State and lifecycle detail have separate budgets and explicit counts and
truncation metadata. Summaries preserve normalized state-class counts;
sensitive condition labels remain undisclosed. Omitted lifecycle detail stays
unknown. Label summaries cap distinct status strings and report omissions.
Dense visible state-summary counting can still depend on the number of intervals.

Density summaries preserve complete type counters internally so merged top
types remain exact. Dense types use bisections and aligned reusable cells;
many sparse types use a whole-page sweep. Thread-safe transactional cache
publication prevents cancelled partial pages becoming cached results.

The browser uses stable resolution levels, aligned pages, and cache identity
including revision endpoint, context and capture bounds. Cached gesture previews
retain their actual original time boundaries and are labelled cached/refining.
Superseded requests abort, and late responses cannot replace current data.
Core drains the JSON body before monitoring disconnects and passes a cooperative
probe into timeline/density queries. Cancellation is observed at checkpoints;
it does not interrupt arbitrary plug-in code or cold archive loading.

No plug-in hook or `IndexedHistory` member was added. Generic indexing,
aggregation, HTTP and cancellation remain core-owned. An unindexed source keeps
one full event-window scan plus lane checks over matching events; its transient
window lists are deliberately uncached. Cold normalized-history materialization
and the initial memory footprint remain separate work.

## Measurements

Single-process synthetic comparison with checkpoint `4609c61`, using Python
3.12 in the installed demo environment on the shared host:

| Query | Checkpoint | Updated |
|---|---:|---:|
| 100K events, one lane, cold overview | 1.745 s | 0.323 s |
| Same overview, warm | 1.769 s | 0.0149 s |
| Ten-event close-up, warm | 0.0118 s | 0.00061 s |
| 1M timestamps, 180 density bins, cold | 0.825 s | 0.00592 s |
| Same density query, warm | 0.844 s | 0.00121 s |

The overview used a 20-glyph budget. A separate instrumented repeat counted
100,000 event projections before the change and 1,000 afterward; all 100,000
events remained counted. Timing samples above are uninstrumented. Density uses
lightweight timestamp indexes, not a million rich event objects. These samples
exclude ingestion, archive loading, browser rendering and peak memory; they
are not production latency guarantees. Raw script/results remain locally under
`.runtime/zoom-improvements/benchmark.py` and `benchmark.json`.

A subsequent [full-node measurement](million-node-measurement-2026-10-02.md)
covers rich-history loading, first search, memory, and A → B → A switching with
1,250,005 events in PE-A. It measures the remaining ingestion/search costs;
it does not replace the zoom-query comparison above.

## Verification and corrections

- Frontend asset/import/syntax checks and all 383 frontend tests passed.
- Core timeline, density, cancellation, query parity, cluster detail, API bounds,
  normalized-data and authoring-document smoke checks passed. An initial broad
  invocation named a nonexistent `test_scale_history_api` module; its 95 real
  tests passed, and the actual `test_scale_history_stream_api` module was run
  subsequently. The typo is retained in the local log, not counted as a pass.
- Broader scale checks caught a high-cardinality density regression: looping
  over type maps once per cell. The adaptive whole-page sparse path fixes it;
  a new test proves one cold type-map sweep and no additional warm sweep.
- Review caught an unindexed fallback cost regression. It now retains the
  original window-first scan. A 10K-event, 33-lane, two-event window checks only
  66 resource memberships after the one window query.
- Threaded tests cover cache integrity, source replacement, cancellation and
  no partial publication. HTTP tests cover body draining, context cleanup and
  disconnect-to-worker cancellation with 499 and no partial bins.
- Source-wiring tests were updated for the extracted frontend helper and the
  checkpoint's concurrent startup. Behavior remains covered by Node tests.
- API declaration inventory, strict package typing (143 modules), public
  consumer typing (two files), generated stubs and fatal-error lint passed.

Local logs are under `.runtime/zoom-improvements`. Tests overlap across focused
runs; their totals are not added into a claim of exhaustive repository coverage.

## Skill trials

Fresh `gpt-6.1-sol` agents had no conversation history. Prompts contained only
the task, skill path and isolated output directory. No implementation steps,
API hints or expected assertions were supplied.

The author trial built an importable burst-event plug-in and used real ingestion
before querying its normalized dataset. It checked 180 events and source records,
stable identities, wide/same-timestamp/empty windows, and malformed/oversized
input. Parent replay passed. This is a tiny parser acceptance trial, not durable
storage or a large-corpus benchmark.

The initial combined validator exercised real HTTP timeline/density/detail,
redaction, revision switching and same-ID runtime replacement, alongside existing
cancellation checks. Its 31 distinct tests passed after correcting an interpreter
without web dependencies. Parent replay passed. The supporting validation map
was then expanded to explicitly cover sparse type cardinality and the unindexed
fallback; a fresh combined agent repeated the task against that final guidance.
That final pass ran 75 tests, including a new indexed/fallback combined scenario,
with no failures or skips. Its Node invocation hit the sandbox path restriction;
the parent's permitted frontend run passed all 383 tests and the browser check
below supplied the live UI evidence. Parent replay of the final combined test
also passed. Neither trial's environment failures were counted as product passes.

Author skill SHA-256:
`5BA7704F6161A09EFF966246C9F96D41454CED923C77F5968A6BCC3DB05D1CDB`.
Validator skill SHA-256:
`410789ECD15EB146F958B4265977E60C5FDF048E5531EF41D07011C122B78031`.
Final validation-map SHA-256:
`E8708C85B12E727E9202C7B66F1BDCA5E5241B5A25BDA2EF48873071E85E3F0D`.
Prompts, reports and executable artifacts are retained in
`.runtime/zoom-skill-trials`; both skill format checks passed.

## Browser and documentation

The retained small assembly ran on port 8880. PE-A loaded 305 events and 130
resources. Rapid zoom/pan settled at an 8× view with 1,440 logical density bins.
Selecting 600.000–600.010 seconds zoomed to the burst, showing 60 events and four
failures while rendering only visible bins from 11,796,480 logical bins. No
browser console errors were reported. The screenshot is retained locally as
`.runtime/zoom-improvements/demo-zoom.jpg`. Existing horizontal overflow remains
visible; this change does not address the earlier layout follow-up.

The documentation drift check updated the quickstart, normative contract,
author guide, runnable example README, API/architecture references, frontend
guidance and README links. The example still requires no zoom-specific hook.
