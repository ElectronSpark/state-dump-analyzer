# Repeated frontend navigation audit — 2026-10-21

Audited commit: `f8ff21d0154d46c955ffb29acdc0005c22214704`.
Target: the live local demo at `http://127.0.0.1:8883/node#overview`, using
`router-state-lab-algorithms-2026-10-02.tgz`, node-a revision
`demo/node-a/revision-0001`: 1,250,005 normalized events and 7,510 resources.
The existing browser viewport was 608 × 668 CSS pixels; no viewport override
was introduced for this pass.

This is a new exploratory audit after the [previous repairs](audit-repairs-2026-10-21.md).
It records four new findings: three functional defects and one measured
performance defect. No application code was changed during the audit; the
subsequent repair and validation are recorded below. It does not claim
exhaustive coverage of the frontend, the earlier 600-case plan, or other
viewport sizes.

## Findings

| ID | Priority | Finding |
| --- | --- | --- |
| RF01 | P2 | Dense source-record clusters open neighboring records on pointer activation. |
| RF02 | P2 | Timeline reveals can focus a target completely outside the horizontal scrollport. |
| RF03 | P2 | A source-to-log jump focuses the correct row below the browser viewport. |
| RF04 | P2 | Merged event/source log navigation repeatedly scans and sorts the million-event stream. |

### RF01 — Source-cluster hit targets still overlap

Reproduction:

1. Enable the **Unmatched CTF records** lane and Fit the capture (1×).
2. Inspect the source clusters near +120 s. The first cluster contains
   `source-ctf-unmatched-000001` through `000036`, starting at +120.100 s.
3. Click that cluster's center.
4. Close its popup, focus the same cluster with the keyboard, and press Enter.

The pointer opens cluster `000109` through `000144`, starting at +130.900 s.
Keyboard activation opens the intended `000001` cluster. The pointer mismatch
was reproduced twice for `000001` and independently for `000073`, which opened
`000181` (+138.100 s). DOM hit testing found that 17 of 19 tested source-cluster
centers inside the visible scrollport hit a different source cluster.

The first two centers are only 3.5 px apart, but each cluster is 23 px wide.
`sourceRecordLanesHtml()` renders `buildSourceGlyphs()` directly, bypassing
the normalized-event `timelineGlyphLayout()` footprint constraints. Source
CSS retains fixed-width clusters. This is a source-lane sibling of the repaired
EX09 event-marker defect, rather than evidence that the normalized-event repair
failed.

Relevant code: `frontend/assets/app.js:3266` and
`frontend/assets/styles.css:6140`. Reuse the existing footprint/layout logic
for source markers, preserving record identities and counts; cover selected
markers, distinct adjacent centers, tied times, and zoom changes.

Evidence: `source-cluster-hit-test-initial.json`,
`source-repeat-confirmation.json`, `source-pointer-mismatch.json`,
`source-keyboard-control.json`, and their PNG captures in the local evidence
directory described below.

### RF02 — Reveal does not reconcile horizontal visibility

Reproduction:

1. Use 10× zoom, center near +120 s, then pan earlier to approximately
   +77.1–149.1 s.
2. From the event log, reveal `source-ctf-unmatched-000003` (+120.300 s).
3. Repeat with normalized event `node-a/scale-event-00000000` (+120.000 s).

Both reveals focus the correct timeline destination, but the destination is
completely outside the visible horizontal scrollport:

| Destination | Target X bounds | Scrollport X bounds | Retained scrollLeft |
| --- | --- | --- | --- |
| Source cluster containing `000003` | 637.9–660.9 px | 12.8–580.0 px | 8 px |
| Normalized event `00000000` | 624.9–636.9 px | 12.8–580.0 px | 8 px |

The timeline has 910 px of content in a 567 px scrollport. The selected time
is inside the logical time window, so time-window recentering does not run.
`scrollTimelineTargetIntoView()` corrects only vertical geometry, and both
reveal paths pass the lane row before focusing the actual marker with
`preventScroll: true`. No step brings the marker into the visible horizontal
columns. Vertical focus placement worked in these cases.

Relevant code: `frontend/assets/app.js:4461`, `:4513`, `:4569`, and `:4654`.
Extend the existing visibility reconciliation to the actual target's horizontal
bounds, accounting for the label column and retaining navigation ownership.
This is distinct from SN012's repaired sticky-header occlusion.

Evidence: `source-reveal-offscreen.json/.png` and
`event-reveal-offscreen.json/.png`.

### RF03 — Log jump focuses an invisible row

Reproduction:

1. Start with normalized events enabled in the log and CTF records excluded.
2. Open the first Unmatched CTF cluster with the keyboard.
3. Ctrl-click its `source-ctf-unmatched-000002` record.
4. After the merged log settles, repeat with `source-ctf-unmatched-000003`.

The CTF source group is enabled correctly and the exact source UID receives
focus. However, the first target was at Y=1108–1152 px in a 668 px-high browser.
The repeated, settled jump left the second target at Y=711–755 px. Its inner
table viewport started at Y=525 px. The selected row was therefore still below
the browser viewport even though it was correctly positioned inside the table.
At the second capture the global loading indicator was hidden and dashboard
data had settled at +120.300 s.

`focusServerEventLogTarget()` positions the inner virtual table, scrolls the
whole `#event-log` section using `smooth/nearest`, then focuses the row with
`preventScroll: true`. It does not reconcile the row's actual bounds against
the browser viewport. The tall controls at this narrow width are sufficient
to expose the gap; later component reflow may compound it but was not isolated.
The pinned source popup also remains over the destination section; this is
supporting UX evidence, not a separately counted bug.

In the settled JSON capture, the field named `loading` stores the loading
element's `hidden` property: `true` means the indicator is hidden, not busy.

Relevant code: `frontend/assets/app.js:11167`–`:11187`. Reuse the existing
post-render focus reconciliation for the final row, including the outer page
and sticky header, while retaining the latest navigation owner.

Evidence: `source-locate-merged-log.json`, `source-log-jump-settled.json/.png`.
Subsequent native End navigation eventually focused the correct last record;
no wrong-row or lost-focus regression is claimed.

### RF04 — Merged log page bounds do not bound computation

Browser exploration showed multi-second source-to-log jumps and uncached
Home/End paging after enabling CTF alongside normalized events. To separate
service cost from browser automation/rendering, the live service was left idle
and eight sequential POST requests were timed at the actual UI endpoint:

`/v1/revisions/demo/node-a/revision-0001/event-log/query`

All used empty layer/search filters and limit 120. Each request was repeated
unchanged in the same warm server process.

| Request | Wall time, two repeats | Server CPU time, two repeats |
| --- | --- | --- |
| Normalized-only locate | 0.071 / 0.011 s | 0.016 / 0.016 s |
| CTF-only locate | 0.012 / 0.008 s | 0.016 / 0.000 s |
| Normalized + CTF locate | 2.111 / 4.823 s | 2.109 / 4.797 s |
| Normalized + CTF page at offset 3000 | 2.109 / 4.882 s | 2.156 / 4.844 s |

All eight requests returned HTTP 200 and 120 items. Counts were exactly
1,250,005 normalized, 2,500 CTF, and 1,252,505 merged records. The normalized
target was index 1; source `source-ctf-unmatched-000003` was CTF index 7 and
merged index 3009. The offset-3000 page returned that exact source UID at 3009.
Complete response hashes matched within each repeated pair, establishing
repeat stability, not an independent full-order correctness oracle.

The indexed fast path in `revision_queries.py:1627` only applies when
`source_types` is empty. The merged fallback builds candidate tuples for the
entire population, sorts them, scans for the requested UID, and only then
slices the page (`:1712`–`:1805`). Limit 120 bounds output but not work. The
browser first locates a target and then requests its page if absent
(`frontend/assets/app.js:11242`–`:11260`), so a single uncached jump can require
two full scans/sorts. Repetition does not remove that cost.

A suitable follow-up is an indexed merge of ordered event/source streams with
rank/locate support and bounded page projection. Preserve exact ordering,
source filters, range membership, UID identity, and bounded retained metadata.
These measurements establish the current bottleneck, not a proposed speedup.

Evidence: `event-log-service-timings.json` and reproducible
`measure-event-log.ps1`. These are warm service wall/CPU measurements, not
browser input-to-paint, cold loading, or a new full-navigation memory benchmark.

## Other exercised behavior and limits

- None → Combined → overview failure selection → Separate retained correct
  event/resource identities.
- Eight repeated dashboard resource changes under the Selected preset
  converged on the final resource after asynchronous loading.
- Source-only log jumps, repeated targets, eight distinct transient jump lanes,
  ninth-target rejection, removal, and retry recovered correctly. Rapid
  superseding jumps did not leave all intermediate targets allocated.
- Resource search/kind changes, table selection → combined relationships →
  Ctrl-click graph endpoint navigation, and a 24-resource custom lane set were
  exercised. Combined mode intentionally disables lane-selection presets;
  this was not counted as a bug.
- Three pan → Back → Forward cycles restored exactly the prior displayed
  time windows. Native End navigation resolved the correct last merged record.
- Alternating layouts and inspecting overview failures preserved an explicitly
  hidden layer. A subsequent explicit log Reveal restored that layer and
  selected the correct DTE249 destination after the pending request completed.
- Some locator clicks initially hit outside a horizontally clipped table row.
  They were repeated on visible cells; automation misses were not counted as
  product defects.
- Passive server RSS rose from 3.005 to 3.158 GiB during the broad audit;
  lifetime peak reached 3.475 GiB. These snapshots do not establish a leak.
  RSS decreased by 18.0 MiB during the eight isolated service calls.
- No new application exception or HTTP 500 was found. One Windows Proactor
  `ConnectionResetError` / WinError 10054 recurred before the timing run; it is
  the already documented upstream cleanup limitation, not a new finding.

## Evidence and documentation check

Raw local evidence is retained under
`.runtime/frontend-repeat-2026-10-21/` (ignored by Git). `records.json` contains
the recorded browser check groups; the named JSON/PNG files preserve the
specific reproductions. `runtime-baseline.json`, `runtime-final.json`, and
the service timing artifact distinguish passive observations from controlled
measurements. Local captures are not published by this report.
The final browser state reproduces RF01 in Separate layout; its capture is
`final-source-mismatch.json/.png`.

The plug-in conformance inventory command completed successfully. No product
code or public plug-in behavior changed, so the required author-documentation
drift check found no quickstart, contract, runnable-example, or skill update
needed. Frontend tests were not rerun for this evidence-only audit.

## Repair — 2026-10-21

The repair changes existing core paths without adding a plug-in API or a
retained merge cache:

- **RF01:** source glyph rendering now uses the same center-spacing layout as
  normalized events. CSS constrains both cluster buttons and rotated single
  marks, retaining counts, IDs, selected state, tied-time evidence and normal
  sizing when zoom provides enough room.
- **RF02:** source/event reveals pass the actual destination marker to the
  existing scroll helper. It reconciles both axes against the client viewport
  (excluding scrollbar gutters), sticky labels, and page/timeline headers.
- **RF03:** local and server log jumps share the existing focus routine. After
  virtual rendering, it measures the actual row and scrolls the outer page
  before focus. It preserves the calculated inner virtual scroll position;
  native row centering could perturb that position and move the logical target
  on the next compressed-scroll repaint. Jumps also dismiss the previous popup.
- **RF04:** unfiltered indexed merges keep normalized events implicit, sort the
  selected source records, binary-rank their insertion positions, and project
  only the requested page. Locate uses the existing UID ordinal index when
  complete and unique; legacy first-match handling remains for duplicate or
  missing identities. Range-first grouping, equal-time order, untimed sources,
  filtering and redaction keep their existing semantics.

### Fresh 1M memory and CPU measurements

The same 286,496,584-byte archive was loaded in separate fresh Python children
from immutable baseline/current source snapshots. Each ran the existing 40
navigation/search phases plus twelve log locate/page probes, with an empty
search cache, fixed hash seed and 100 ms memory sampling. Both completed all
52 phases with exit code 0, empty stderr and no memory/time guard activation.

| Metric | Before (`f8ff21d`) | After |
| --- | ---: | ---: |
| Loaded RSS | 2.356 GiB | 2.358 GiB |
| Lifetime peak RSS across the workload | 2.760 GiB | 2.438 GiB |
| Eight merged-query probes, total CPU | 21.391 s | 0.078 s |
| Merged locate/page wall latency | 2.107–3.884 s | 12.4–15.8 ms |
| All measured phases, summed CPU | 195.750 s | 170.828 s |
| Unchanged 40 phases, summed CPU | 174.344 s | 170.734 s |
| Search sidecar size | 75,038,720 bytes | 75,038,720 bytes |

Peak RSS decreased by **330.44 MiB (11.69%)**. All **35 complete query-response
hashes**, phase result summaries and cache-retirement observations matched.
Loaded memory and storage are effectively unchanged. The unchanged-phase CPU
difference is not evidence of an additional optimization.

These are service-process measurements, excluding HTTP/browser work. The OS
file cache was not cleared; fast individual CPU samples reach timer resolution.
The merge has 1,250,005 normalized events and 2,500 selected CTF records. It
eliminates the million-event materialization, but sorting/ranking still scales
with selected source count. Layer/search-filtered merges retain their exact
fallback; this is not a claim of page-only work for every filter or a million
source records.

Artifacts are under `.runtime/repeat-repairs-2026-10-21/`: `summary.json`,
`comparison.json`, provenance/source snapshots, and each run's `result.json`,
`child.jsonl`, `memory.jsonl` and `stderr.log`. They are local ignored evidence.

### Browser verification

The primary agent restarted the live demo with the repaired backend and
reloaded the frontend. All four findings are resolved in the tested workflows:

- **RF01:** repeated pointer activation opened `000001`, `000073`, and
  `000001`, each with the intended records. Keyboard activation agreed.
  After zooming and log/timeline round trips, **22 of 22** source-marker centers
  inside the usable client area hit their own identity. This includes the
  selected first cluster, whose footprint is 3.5 px at Fit and 23 px at 10×.
  The count excludes sticky labels and scrollbar gutters, rather than treating
  every point inside the outer border box as an accessible marker.
- **RF02:** with the same +77.1–149.1 s logical window and a 608 × 668 viewport,
  Back/Forward restored horizontal scroll to zero before Reveal. Source
  `000003` then focused its correct cluster at X533.6–556.6; normalized event
  `node-a/scale-event-00000000` focused its correct mark at X545.1–557.1.
  Both fit between the sticky label and the usable right edge, X564.8, with
  vertical visibility preserved.
- **RF03:** repeated source-to-log jumps restored the CTF group and focused
  `source-ctf-unmatched-000003` at Y342.3–386.3 in the normal viewport.
  A temporary 608 × 480 viewport exercised the log's 300 px minimum height
  (283 px client height): the same row remained visible at Y247.6–291.6,
  below the sticky table header ending at Y146.0. Restoring the original
  viewport retained the exact focused row. The temporary override was reset.
- **RF04:** the original eight warm live HTTP requests were repeated after
  browser work became idle. All returned HTTP 200 and identical raw response
  SHA-256 hashes compared with the audit. Merged locate fell from 2.111–4.823 s
  to 23.4–23.8 ms; its destination page fell from 2.109–4.882 s to 17.1–17.9 ms.
  Normalized-only and source-only behavior remained correct. These include
  HTTP overhead but still are not browser input-to-paint measurements.

Browser evidence is in the repair artifact directory's `browser/` subfolder:
`rf01-final-hits.json`, `rf01-selected-final.json`,
`rf01-keyboard-final.json`, `rf02-source-final.json/.png`,
`rf02-event-final.json/.png`, `rf03-final-source-log.json`,
`rf03-short-viewport.json/.png`, and `final-verified-source-cluster.png`.
`event-log-service-timings.json` and `event-log-service-comparison.json`
preserve the live HTTP comparison. No browser console error or new server
exception was observed in this repair pass.

### Checks and documentation stewardship

- `npm --prefix frontend run check`: **514 passed** (497 top-level tests),
  including the final scrollbar and compressed-scroll corrections.
- `python -m unittest tests.test_scale_history_frontend
  tests.test_frontend_audit_regressions -v`: **63 passed**.
- Backend history/query/untimed/API checks: **48 passed, 686 subtests passed**.
  Command: `python -m pytest -q tests/test_history_query_algorithms.py
  tests/test_revision_queries.py tests/test_untimed_event_log.py
  tests/test_scale_history_stream_api.py`.
  The differential matrix compares complete indexed merge payloads with the
  existing exact-sort fallback. A virtual-million test rejects unbounded event
  traversal and reads fewer than 25 event payloads across deep page/locate cases.
- `tests.test_plugin_authoring_docs`: **18 passed**, including the documented
  example/smoke commands. The conformance inventory command also completed.
- Both updated skills passed `quick_validate.py`; `git diff --check` passed.

The initial sandbox run blocked localhost proxy tests and the default temporary
directory. Final checks used the authorized localhost execution environment and
a repository-local test temporary directory; those infrastructure failures were
not treated as product failures or repaired by weakening tests.

`router-plugin-author`, `router-plugin-validate`, and their validation map now
cover shared source/event glyph spacing, actual destination visibility across
both scroll axes and containers, and merged locate-plus-page work/memory bounds.
The required author-documentation drift review found no public plug-in hook,
schema, emission, example, or command change. Quickstart, normative contract,
guide, runnable example and README therefore need no unrelated edits.
