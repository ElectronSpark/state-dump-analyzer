# History algorithm improvements — 2026-10-02

The previous work was committed before implementation as `2725b0b`
(`Optimize zoom queries and record full-scale performance investigations`).
This follow-up implements five algorithm changes in core and an optional
ordered-history accelerator in the demo adapter.

## Completed implementation

- [x] Own derived caches by the exact immutable history generation. Retiring
  a node no longer leaves its history pinned by a long-lived service's density,
  timeline or event-union cache. Active readers can finish; same-revision
  replacements cannot reuse the old generation's cache. Immutable adapters
  that reject private cache state use the request-local fallback.
- [x] Store exact search results adaptively as sparse ordinals, complement
  ordinals or bitmap/rank buffers. Retention is bounded by encoded bytes and
  query count. Dense results can remain cached, and bounded slices do not
  expand all matches into Python objects.
- [x] Reuse selective shorter-needle results for exact literal refinement.
  Cache layer-filtered event ordinals across pages under a separate 4 MiB
  generation-local budget. Broad or unavailable candidate sets retain the
  complete exact search path.
- [x] Bisect optional canonically ordered resource event lanes for cold narrow
  timeline windows. Deduplicate only the selected event windows when a complete
  cached union is unavailable and the selection is narrow or over budget.
- [x] Collect first-query matches during safe corpus construction or mandatory
  sidecar validation. Publish only after complete integrity checks; invalid
  partial validation results cannot escape through the query cache.

The plug-in still owns device meaning and history production. Core owns
search, cache ownership and timeline algorithms. Ordinary parser capabilities
and the required `IndexedHistory` protocol are unchanged.

## Verification

The configured Conda Python 3.12.13 interpreter was used for parent checks.
Relevant results (overlapping suites are not additive):

- History generation ownership, timeline/density and revision queries:
  36 tests passed.
- Search, stream API, cluster details, cancellation, API security and assembly
  store: 95 tests completed successfully, one platform skip.
- Six new standalone search algorithm checks now explicitly register with the
  documented `unittest` runner; all six passed. The independent skill validator
  noticed their original free-function form was not collected by `unittest`.
- Typing-contract and density recheck: 17 tests passed after fixing missing
  generated annotations. Strict source typing passed for all five changed core
  algorithm modules; strict public package and consumer checks passed.
- Demo tests: 29 passed. The runnable author-documentation smoke block and
  associated checks passed (18 tests). Relevant frontend/loading/archive checks
  passed; the only initial boundary-suite failure was the corrected stub issue.
- Ruff's documented error selection and `git diff --check` passed.

An additional full conformance run was stopped during the expensive multi-node
route scenarios after more than 560 successful checks. It is not claimed as a
completed full audit. The new algorithm suites are now included in the
presentation conformance group.

## Skills exercised by GPT-6.1 Sol

Fresh agents used the skills with no inherited conversation and no API hints.
Initial trials revealed that source-only import paths could hide selection of
an interpreter without the demo web dependencies. The skills now route authors
to interpreter discovery and import verification before executing tests.

Final author prompt:

> Use .agents/skills/router-plugin-author/SKILL.md to build and demonstrate a small synthetic plug-in with history search and timeline queries. Put all artifacts and a report under .runtime/algorithm-skill-author-final. Treat production files as read-only.

Final validation prompt:

> Use .agents/skills/router-plugin-validate/SKILL.md to validate combined history loading, cache lifetime, search and timeline behavior. Put executable checks and a report under .runtime/algorithm-skill-combined-final. Treat production files as read-only.

The fixed final skill hashes are:

- Author: `e470ddce0c1d8f75156c427e567e5afd51d0cedbf96066871f700ff70d05cf72`.
- Validator: `0d171e7fdd271ccfdaa6c0fb6b59d75c04f414db8662af59da49b0719cd9187c`.

The author trial ingested 64 semantic events, three resources and four retained
status records. Search pages and wide, same-timestamp and empty timeline windows
matched raw references. Its separate corpus retained 168 bytes within a
256-byte result budget. Malformed and oversized input was rejected.

The combined trial completed 58 checks: 57 passed and one Windows symlink
privilege skip. It covered loading leases, concurrent loading, generation
replacement/retirement, literal refinement, dense results, layer pages and
timeline reference parity. Its narrow timeline queries visited 94 records in
total across a 30,000-record lane; retained search results occupied 760 of
4096 encoded bytes. Both final trial drivers were reproduced by the parent.
These synthetic checks establish correctness and visited-work bounds, not
million-event latency. Both skill format validators passed.

## Full-scale measurement

The regenerated PE-A contains 1,250,005 events and 7,510 resources. A fresh
process and empty search-sidecar directory exercised A load, searches and
density queries, then B load, A reload and validated sidecar reuse. The broad
test process was stopped before measurement. The supervisor sampled memory
every 100 ms and checked Windows lifetime peaks. The run completed in
208.44 seconds with exit code zero, empty stderr and no guard activation.

| Operation | Wall time | Result |
| --- | ---: | --- |
| Prepare ten-node archive | 18.468 s | Node packs and projections prepared |
| Load PE-A history | 25.877 s | 1,250,005 events |
| First `failure` query, including safe corpus build | 80.423 s | 24,925 matches |
| Repeat `failure` | 4.30 ms | Same exact count |
| First `success` query on the ready corpus | 3.181 s | 1,225,080 matches |
| Repeat `success`, five requests | 15.12–16.21 ms | Median 15.24 ms |
| `fail` then refined `failu` | 2.797 s / 1.807 s | 191,427 / 24,925 matches |
| Refine cached `failure` with an absent suffix | 109.2 ms | Exact zero matches |
| First Control plane + `success` page | 1.535 s | 354,505 matches |
| Subsequent filtered pages, offsets 0/100/1000 | 6.42–11.71 ms | Exact counts and bounded pages |
| First / warm 256-bin density query | 7.74 / 1.42–1.47 ms | Complete capture partition |
| Switch to PE-B / return to PE-A | 30.726 / 30.275 s | One cached history |
| Returned PE-A search, including sidecar validation | 4.736 s | 24,925 matches |

The dense result retains **101,048 bytes** as a complement, versus 4,900,320
bytes for its raw uint32 ordinal payload (about 98% smaller). It now remains
cached under the byte budget. The prior ordinal-count budget evicted this
result immediately. These are result-buffer figures, not total process RAM.

After density queries and switching to B, a weak reference confirmed the old
A runtime was reclaimed. Service-rooted density/timeline/filter caches were
absent. PE-A's loaded working set was **3.22 GiB**; process peak was **6.35 GiB**
during navigation and final working set after close/GC was **0.145 GiB**. The
safe-text SQLite sidecar remains **2,492,391,424 bytes**. Main history memory,
navigation overlap and persisted corpus size remain substantial bottlenecks.

The [earlier measurement](million-node-measurement-2026-10-02.md) recorded
106.255 seconds for first search and 11.301 seconds for returned-sidecar search.
Those historical numbers are not a controlled A/B comparison: the regenerated
archive has four additional PE-A resources, the OS cache was not flushed, and
each cold path was measured once. The fused-pass tests establish avoided work;
the entire cold-time difference must not be attributed to that optimization.
This is a direct backend measurement, not browser or network latency.

Reproduce with the task-local harness and a new output directory:

```powershell
python -X utf8 .runtime/algorithm-improvements/measure.py --archive demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --output .runtime/algorithm-improvements/after-full-new --repeats 5 --dense-term success
```

Raw phases, process memory and retirement observations are in
`.runtime/algorithm-improvements/after-full/result.json`, `child.jsonl` and
`memory.jsonl`. The fresh search cache path is recorded in `result.json`.

## Regenerated samples and browser check

Regenerated and verified the teaching status fixture and runtime-v2 ingestion
corpus. Their deterministic tracked contents did not change.

Generated a fresh full-scale archive:

- `demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz`
- 286,496,584 bytes; ten full-scale node dumps and 41 coverage cases.
- SHA-256: `4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
- Both `--check-launchable` and `--validate ... --deep-validate` passed.

The dated filename preserves the earlier measurement archive. Regeneration:

```powershell
python -X utf8 -m rsl_demo_generator --ensure-launchable demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --force-rebuild --path-only
python -X utf8 -m rsl_demo_generator --check-launchable demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz
python -X utf8 -m rsl_demo_generator --validate demo/fixtures/router-state-lab-algorithms-2026-10-02.tgz --deep-validate
```

A separate newly generated small archive was browsed with current code at
`http://127.0.0.1:8882/node#timeline`. PE-A loaded 1,205 events and 210 resources.
Zoom changed from 1 to 1.5. Searching `success` returned 1,183 records, then
selecting Control plane returned 345. No browser warning/error entries were
captured. This verifies the bounded browser path, not full-scale browser latency.

Recorded UI issue: the small `--allow-small` archive is labelled "Full-scale
mode" in the analysis banner. The archive is correctly generated as non-full-scale;
the banner wording should distinguish indexed history from fixture scale.

### Full-scale browser follow-up

At the user's request, launched the regenerated archive on a fresh server at
`http://127.0.0.1:8883/node`, with an empty search-cache directory. The browser
rendered PE-A's **1,250,005 events and 7,510 resources** and the 13 selected
resource lanes. Two zoom steps reached 2.25x and completed density refinement.
The loaded page was observed 83 seconds after navigation; this is an observation
upper bound, not an instrumented first-render measurement.

Browser search returned the same exact counts as the backend measurement:
24,925 for `failure`, 1,225,080 for `success`, and 354,505 for `success` filtered
to Control plane. The cold search showed "Building query indexes" and a loading
history placeholder instead of reporting a partial count. It was still pending
at 75 seconds and complete at the next observation at 110 seconds. Browser
console error/warning capture was empty. Server working set was approximately
3.87 GiB, with a 3.88 GiB observed process peak during this single-node session.

The larger stream exposed a reproducible viewport issue:

1. Search `success`, optionally select Control plane, then focus the event-log
   scroller and press End.
2. The final records are fetched and present in the DOM, but almost the whole
   viewport is blank. This occurs with both 354,505 filtered and 1,225,080
   unfiltered matches.
3. At the bottom, the scroller has height 8,000,032 px and a 384 px viewport.
   A trailing spacer occupies 340 px, leaving the final data row near the
   sticky header instead of filling the viewport with the last page.

Follow-up: correct the capped-scroll window/spacer calculation in
`frontend/assets/view_models.js` together with its table/header integration in
`frontend/assets/app.js`. Exact backend counts remain correct. This browser
validation records the defect; it does not change frontend behavior.

The server also logged one Windows asyncio `ConnectionResetError` (10054)
during interaction; requests and the UI continued working. The triggering
connection was not identified, so its cause is not attributed to a particular
action. A fresh GPT-6.1 Sol source review additionally found stale embedded
`client_contract` wording in the demo adapter claiming compact events transfer
to the browser; the actual bootstrap is server-windowed. Review, server logs
and the test search corpus are under `.runtime/algorithm-million-browser`.

This follow-up changes only validation evidence. The plug-in-documentation
drift check found no additional author-visible API changes requiring skill,
contract or example modifications.

### End-of-log viewport diagnosis

Confirmed a frontend geometry defect in `virtualScrollWindow`, independently
reviewed by GPT-6.1 Sol. When the logical list exceeds the 8,000,000 px cap,
`virtualScrollScale` maps the bottom scroll position to the **last row index**.
The window calculation then positions that anchor at the viewport top. Most
of the fetched tail rows sit above the viewport, and a bottom spacer fills
the space below the last row. Fetching more data cannot correct this placement.

For the observed 384 px viewport and 44 px rows, the calculation is:

- Body scroll surface: 8,000,000 px; bounded scroll position: 7,999,616 px.
- Rendered window: 29 rows, or 1,276 px; top spacer: 7,998,384 px.
- Last row starts at 7,999,616 px, exactly the bounded scroll position.
- Remaining bottom spacer: 384 - 44 = **340 px**.

The sticky table header aggravates the result. The browser's actual scroll
height is 8,000,032 px, while the helper treats 8,000,000 px as the entire
surface and receives the full `scroll.clientHeight` as its viewport. At the
browser's bottom scroll position, the last row sits beneath the sticky header;
approximately 12 px of the 44 px row remain visible below it. Header height,
body viewport and scroll coordinates need a consistent convention.

A probe importing the production helper reproduced the 340 px spacer at
181,819, 354,506, 1,225,081 and 1,250,006 virtual rows. The extra virtual row is
the stream heading. At 181,818 rows the surface is still uncapped and the
terminal spacer is zero. Evidence is in
`.runtime/algorithm-million-browser/scroll-probe.mjs` and `scroll-probe.json`.
The existing two virtual-scroll tests pass because they check range membership
and the height cap, but never check whether the tail rows fill the viewport.
The targeted run passed 2 tests with 31 tests excluded by the name filter.

The correction should bottom-align the final rendered window, eliminate its
terminal spacer, and account for the sticky header in the usable viewport and
actual scroll range. Keep `virtualScrollTopForIndex` consistent so focus and
locate actions expose the intended row. Regression coverage should assert
physical row visibility and spacer geometry at start, middle and End, across
the cap threshold and viewport sizes, followed by a browser check with the
sticky header and selected-range headings. An upper-bound-only clamp on the
top spacer is insufficient; the independent review verified that it leaves
this failing End calculation unchanged.

This diagnosis changes no production code or public plug-in behavior. Counts
and fetched final records were correct in the reproduced cases. The isolated
Windows connection-reset log entry remains a separate, unattributed issue.
Plug-in-documentation drift check completed; no further skill, contract or
example update is required for this evidence-only addition.

## Scope and remaining work

First-ever redaction/serialization, exact arbitrary corpus searches without a
selective cached candidate, broad cold timeline work and lazy state-interval
hydration can still be linear. The new event-window path does not bound every
state reconstruction operation. Result-cache byte figures exclude the corpus
and full process heap.

Compressed search-block storage, packed event records, block pruning and a
ranked merge for mixed event/source streams remain separate proposals from the
[storage investigation](compact-storage-investigation-2026-10-02.md). This change
does not reduce the persisted safe-text corpus layout or claim their projected
storage savings.

Plug-in-documentation drift check completed. Updated the quickstart, guide,
normative contract, API/architecture references, runnable example README,
root links and skills together. The quickstart's smoke commands remain runnable;
optional ordered history is exercised by the demo adapter and conformance tests.

### End-of-log viewport fix (2026-10-03)

The virtual scroll mapping preserves physical row spacing at the head and tail,
compressing the middle and mapping the physical bottom to the last full logical
viewport. Rendering retains fractional row offsets and one partial extra row;
focus navigation inverts the same mapping with the renderer's overscan. This
also fixes the near-tail focus failure found during independent validation.
Event-log rendering and all three focus-navigation paths use the body
viewport below the measured sticky table header. This removes the terminal
blank spacer in the production-helper regression for 181,818, 181,819, 354,506,
1,225,081 and 1,250,006 rows, including both sides of the height cap.

`cd frontend; npm run check` passed the frontend contract check and all 387 tests.
The author skill now calls out capped-scroll and sticky-header geometry checks;
its skill-format validator passed. An independent geometry sweep passed 45,132
checks with no failures. The plug-in-documentation drift check found
no author-visible API or example change, so no contract or quickstart update was
required. These checks establish helper geometry and frontend integration
contracts; the browser checks below establish the actual visible result.

The live full-scale browser follow-up confirmed End displays eight visible rows
with no trailing spacer and the final row fully visible. It then exposed lost
keyboard focus after delayed scroll rerenders. The renderer now retains the
active row identity before replacing the table body and restores focus to its
replacement with `preventScroll`. Two executable renderer regressions verify
repeated delayed rerenders and preservation of focus in external controls.
The parent agent reloaded the final build and verified eleven consecutive
ArrowUp moves from the final record to selection index 1,249,993. Focus remained
on that row after rendering settled, with its bounds at approximately 187–231 px
inside the 384 px scroller and below the sticky header. Search focus also
survived asynchronous result refresh.

The live browser showed eight visible tail rows and no trailing spacer for
1,250,005 unfiltered events, 1,225,080 `success` matches, and 354,505 Control
plane `success` matches. A selected range of +600 to +610 seconds introduced
Selected period / Other records headings; End still showed eight rows with
no terminal spacer. No browser warnings or errors were captured. The complete
stream was restored and left at End on `http://127.0.0.1:8883/node`.

GPT-6.1 Sol implemented the change using the author skill with a fresh context
and this dispatch: "Use the router-plugin-author skill to fix the documented
blank viewport at End in the million-event log. Update the skill if needed and
validate your changes. Preserve unrelated work." Parent validation found the
near-tail geometry and delayed-focus failures; follow-ups supplied failing
outcomes for Sol to repair. The parent inspected the changes, reran the
45,132-check geometry sweep, and performed the browser checks above.

A fresh GPT-6.1 Sol trial used the final skill with: "Use the
router-plugin-author skill to validate large-scale event-log navigation. Put
evidence under .runtime/scroll-skill-final. Production files are read-only."
Its 37 focused frontend tests, 12 Python frontend-wiring tests and geometry
sweep passed. This trial did not operate the browser. Skill/source hashes and
raw results are in `.runtime/scroll-skill-final`; the parent trial metadata and
screenshot are in `.runtime/scroll-fix-validation`.
