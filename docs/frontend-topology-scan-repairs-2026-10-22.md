# Off-screen popup and temporal scan repairs — 2026-10-22 UTC

The FP04 off-screen popup defect and the repeated temporal-topology scan cost
are repaired. This follows the findings in
[the earlier audit](frontend-popup-state-audit-2026-10-22.md). Existing uncommitted
FP01–FP03 repairs were preserved and included in this task's baseline; HEAD
`4a1d872` is a reference, not a clean before version. No commit or push was
requested.

## Root causes and changes

`positionHover()` used the anchor's bounding rectangle without intersecting it
with its visible area. A pinned card could remain over the Lanes trigger after
the anchor had scrolled off-screen. The existing positioning function now
intersects the anchor with the document and its own timeline/log scrollport,
including sticky headers and lane labels. It closes a fully clipped or removed
anchor, preserves positive visible slivers, and clamps the card inside the
viewport. Scrollback does not revive a dismissed card. Hidden cards do not bind
actions or start cluster-detail work.

Native browser validation exposed two activation edges while implementing that
rule: smooth focus scrolling had not finished when visibility was checked, and
native nearest alignment could put an upward source target underneath the
sticky header. The existing focus handler now finishes the nearest reveal
immediately. If the target remains fully behind a sticky header or lane label,
it reuses `scrollTimelineTargetIntoView()`; that helper now recognizes the
resource label shell. Visible and partly visible targets keep nearest alignment.
Virtual-log rows retain their existing compressed-scroll positioning. Passive
focus restoration during timeline/density redraws uses a scoped guard in the
existing restore helper: it preserves scroll and still applies popup visibility
checks. This distinguishes explicit activation from restoring keyboard focus.
There is no new popup timer, persistent cache, or reveal subsystem.

`TemporalTopologyService._relationship_views()` previously rescanned every
selected endpoint's history at every uncertainty-window probe. The 80-row
response limit applied after this work. The indexed path now walks each endpoint
entry once, validates its bounds once, and uses binary searches to find the
existing probes covered by that interval. It populates those probes in the
original endpoint/list order. Raw dictionaries are converted to the prior list
representation and released before filtering, avoiding overlapping raw and
filtered dictionary indexes.

The probe set is unchanged, including the existing last-identity probe selection.
Half-open and unbounded intervals, validation of excluded entries, overwrite
before filtering, tri-state presence, center-or-first representative selection,
ordering and limits remain intact. Callback providers keep their original
ordered per-probe calls and filter-before-dedup semantics. No persistent cache,
index, public API or plug-in semantic responsibility was added.

## Browser validation

Parent validation used the actual local demo at `http://127.0.0.1:8883/node`,
608 × 668 CSS pixels, with 1,250,005 events, 7,510 resources and 5,000 retained
source records. The final backend process is PID 37236. Actions used ordinary
pointer, native keyboard, range, lane, pan, log and topology controls; DOM reads
only observed visible content and geometry. No state injection or direct API
calls were used to drive the browser checks.

- Repeated normalized-cluster pin → range Apply/Clear → Lanes clicks. Once the
  anchor left the screen the card closed and the picker remained clickable.
- Enter/Space activation of a normalized cluster below the viewport and source
  `source-ctf-unmatched-000502` above it. The final source card stayed open after
  focus settled, clear of the sticky header, and inside the viewport.
- Native nested scrolling moved a pinned source anchor partially behind the
  header: its rectangle was y244.041–258.184, with the clipping boundary at
  y250.512. The remaining 7.672-pixel sliver kept the card open. Another scroll
  fully clipped it and closed the card. Returning scrollTop to zero left it
  closed; an explicit pointer click reopened the correct source.
- Horizontal pan removed the old source anchor and dismissed its card; Back
  restored the viewport and explicit activation reopened the source.
- A focused virtual-log row opened its card against its own viewport while the
  timeline was far off-screen. Timeline clipping was not applied to that row.
- Final review found and the browser reproduced an intermediate regression:
  after scrolling a focused density bin to scrollTop 200.8, the background density
  refresh restored focus and forced scrollTop back to 6.4, reopening the card.
  With the scoped restoration guard, the same sequence retains scrollTop 200.8
  and keyboard identity while the card stays closed. Scrolling back to zero
  does not revive it. Subsequent explicit source activation still opens correctly.
- Late topology reconstruction, an identical repeat, an early query and return
  to late time completed. The repeated late result showed 80/7,510 resources,
  80/2,435 relationships and 100 bounded changes. Partial node-b status remained
  explicitly labeled; no warning/error console entries were captured.

Browser evidence is in `.runtime/topology-popup-repairs-2026-10-22/browser/`:
`checks.json`, `topology-checks.json`, screenshots and `console-errors.json`.
Intermediate failed focus checks are retained. Three exploratory captures are
annotated because a stationary pointer opened a different hover, or Home did
not actually scroll; later pointer-cleared/native-scroll checks establish
dismissal and no revival. Horizontal sticky-label clipping and the log-header
boundary also have executable DOM tests; the browser horizontal test exercised
pan/removal rather than every pixel of native scrollbar clipping.

## Executable and skill validation

- `npm run check` in `frontend`: **555 passed**, no failures or skips; this
  includes **20** focused popup tests executing production handlers/functions,
  including the real deferred restoration callback and focus handler together.
- New temporal-probe tests compare complete results with a frozen old-scan
  oracle over **250 seeded datasets × 2 paths**, plus interval boundaries,
  duplicate overwrite/filter ordering, presence, limits, malformed bounds and
  provider iteration/error cleanup. The five semantic tests also passed against
  the old implementation; the work-count test asserts the reduced parsing work.
- Initial focused temporal checks: **10 passed**. After the temporary-dictionary
  release adjustment, the probe and temporal-boundary suites passed **18 tests**.
- Integration run: **144/145 passed**. Its failure was an LF-only assertion
  against unchanged CRLF JavaScript; baseline/current asset bytes were identical.
  The assertion now accepts either newline while retaining adjacency and argument
  ordering. The affected test plus temporal HTTP-contract suite passed **12/12**.
- Both repository skills and the linked validation map were updated for exact
  temporal semantics, transient-memory checks, visible-anchor ownership and
  native focus/sticky clipping. Both skills pass `quick_validate.py`; conformance
  inventory passes with the new probe suite included in presentation (17 modules).

- A GPT-6.1-Sol agent used a short skill-directed prompt with prior audits and
  other agents' outputs excluded. Its final same-agent revalidation passed
  **24 temporal tests**, **84 popup/activation tests**, and inventory. It used
  existing repository checks and executable orchestration, not a new independent
  oracle. No browser or performance claims were made. Earlier iterations remain
  preserved; final prompt, hashes, logs and limits are in
  `skill-trial/final-restoration/`. Parent browser validation supplies the native
  focus/scroll evidence separately. This final check is a same-agent continuation,
  not a new blind trial.

Logs, source hashes, measurement harnesses and skill-trial artifacts are retained
under `.runtime/topology-popup-repairs-2026-10-22/`.

## Fresh 1M memory and CPU measurements

The same generated archive contains 1,250,005 events, 7,510 resources and 243,823
relationship intervals (459,898 mutations). Its SHA256 is
`4cea20db78aa3fede9dc79a89a9277c5a9a72905fbff76a5f8436efd1c4aec30`.
Serial before/after runs use configured Python 3.12, fresh child processes,
separate empty search caches, `PYTHONHASHSEED=0`, and 100 ms memory sampling.
The 52-phase navigation/search/log harness is byte-identical to the previous
measurement harness. The separate topology diagnostic calls the production
endpoint under runtime/revision scope, including acquisition and identity checks.

| Service metric | Before | After |
| --- | ---: | ---: |
| Loaded node-A RSS | 2.354553 GiB | 2.354210 GiB |
| Navigation sampled peak RSS | 2.369724 GiB | 2.370453 GiB |
| Overall OS lifetime peak RSS | 2.433586 GiB | 2.432262 GiB |
| All 52 phases, CPU | 166.437500 s | 169.843750 s |
| Supervised wall time | 170.984 s | 173.891 s |

| Topology request | Before CPU / wall | After CPU / wall |
| --- | ---: | ---: |
| Early, +360.200 s | 1.171875 / 1.187594 s | 0.828125 / 0.821372 s |
| Late, +624.9992 s | 20.250000 / 20.547700 s | 0.703125 / 0.700264 s |
| Identical late repeat | 19.250000 / 19.588102 s | 0.671875 / 0.687864 s |

Late-query CPU falls about **96.5% (29× faster)**. All **52 ordered result
summaries**, **35 complete service response hashes**, and **three complete
topology response bodies** match. Topology is separate from the 52-phase harness;
the latter's 2.05% CPU increase in this single pair is not a topology result.
The loaded/navigation/lifetime memory measurements remain approximately stable.

Topology transient memory is mixed: observed first-late RSS growth changes from
**6.07 to 19.55 MiB**, while the repeated-late call changes from **19.07 to
10.27 MiB**. Retained RSS across all three calls is **18.51 to 19.06 MiB**,
including allocator/runtime retention. This is not evidence of a memory
reduction or proof against a long-run leak. It does show the CPU improvement
without a material increase in loaded service memory in this pair.

Before executable source was frozen at 15:41:00 UTC; measured-after source at
16:14:57 UTC. Both 399-file trees are preserved. Only `temporal_topology.py`
changes among 323 backend files. The final passive-focus correction was made
after the measurements and changes only frontend code/tests within that source
scope. It has a separate final snapshot; the final backend is byte-identical to
the measured backend. The service harness does not execute frontend JavaScript.

No browser requests ran during either measurement window: access/error logs did
not grow. The existing server still consumed 9.563 CPU seconds over the wider
318.770-second before observation and 7.906 over 257.948 seconds after. Thus the
browser was inactive, not the whole host CPU-idle. Metrics belong only to the
measured child. OS file cache was not cleared. Endpoint timers exclude response
hashing/serialization, HTTP and browser rendering. Brief memory peaks may be
missed at 100 ms; OS lifetime peaks include setup/loading. This is one serial
pair, not a distribution or browser-heap benchmark. The earlier observation about
broader request-disconnect cancellation remains outside this optimization.

Raw results and provenance are in `measurement-report.json`,
`topology-comparison.json`, and the parent's independent
`parent-verification.json` under the current runtime directory.
Parent verification independently read all ordered results, rehashed all frozen
trees and the archive, compared the full topology bodies, and confirmed the final
working tree matches its separate snapshot. All 323 final backend files match
the measured-after backend exactly.

## Plug-in documentation drift

Completed the `AGENTS.md` stewardship check. These changes preserve public
plug-in discovery, contracts, semantic ownership, examples and author-facing
commands. No quickstart, normative contract or runnable-example update was
needed. The validation map was updated for the new checks. The unrelated fixture
lock was left untouched.
