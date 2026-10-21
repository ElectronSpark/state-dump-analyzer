# Stateful audit repairs — 2026-10-21

This repair pass addresses the 27 findings in the
[stateful audit](audit-600-2026-10-21/findings.md) and six additional findings in
the [repeated-operation audit](repeated-cross-component-audit-2026-10-21.md).
That report's finding 1 is the same defect as SN006; it is counted once.
Three linked defects discovered during repair validation are recorded as EX08
through EX10 below, bringing this pass to 36 distinct repairs.
Historical audit evidence remains unchanged. The 436/600 executed planned
cases and 29 expansion cases describe the pre-repair audit, not validation of
this change or completion of the remaining planned cases.

## Root causes and repair checklist

The validation section distinguishes browser replay, executable regressions,
and measured performance; it does not imply every race was replayed manually.

| Finding | Root cause | Repair area |
| --- | --- | --- |
| SN001 | Expansion reserves half the lane cap before honoring explicit roots; reveal appends its target behind older roots. | Requested-root priority and reveal ordering |
| SN002 | Combined relationships test the root's layer but omit the counterpart's layer. | Existing visibility predicate |
| SN003 | Combined history renders every interval and boundary, bypassing the timeline glyph budget. | Bounded whole-window presentation |
| SN004 | Layer-filter rerender replaces the focused control. | Stable control focus |
| SN005 | Resource selection and bundle handlers rebuild rows without preserving control and tree-instance identity. | Resource-table rendering |
| SN006 | Back, pan and lane hiding do not supersede pending reveal authority. | Existing navigation intent |
| SN007 | Multi-effect reveal enables a recomputed neighbor's layer instead of its chosen target's layer. | Reveal target identity |
| SN008 | Full-range summaries project all events before truncating detail; unchanged bounds repeat the work. | Bounded detail projection and range authority |
| SN009 | Concurrent consumers of an unchanged selection invalidate one another's resolution. | Reuse pending selection resolution |
| SN010 | Disclosure restoration belongs only to the pagination callback. | Same-query correlation rendering |
| SN011 | Pagination restores focus with preventScroll but does not make its target visible. | Focus visibility |
| SN012 | Jump scrolling does not account for the sticky header and subsequent layout changes. | Measured visibility reconciliation |
| SN013 | Retained topology results read a draft clock policy from current controls. | Applied-result provenance |
| SN014 | Search-filtered counts determine tabs and omit the selected zero-result kind. | Explicit kind selection |
| SN015 | The row's Space handler intercepts a nested checkbox's native activation. | Keyboard event ownership |
| MN001 | Cross-node handoffs use the label for intra-node layer disagreement. | Finding presentation |
| MN002 | Missing resolution is conflated with disagreement. | Outcome semantics |
| MN003 | Direction changes retain asymmetric scenario endpoint context. | Route-form synchronization |
| MN004 | Withdrawn historical candidates affect active-path completeness. | Active candidate selection |
| MN005 | Attachment-router labels mask logical external destinations. | Endpoint labeling |
| MN006 | Node navigation links keep an obsolete route query. | Applied navigation context |
| MN007 | Stationary pointer movement events overwrite keyboard hop preview during scrolling. | Interaction ownership |
| MN008 | Traversal-budget stops are presented as missing evidence. | Termination reason presentation |
| MN009 | A route-row seed loses the logical destination descriptor. | Seed identity |
| MN010 | Programmatic direction changes leave start controls and guidance stale. | Shared direction synchronization |
| MN011 | Replacement route seeds/restored context retain an earlier error. | Error ownership |
| MN012 | Equivalent full and minimal start descriptors conflict. | Canonical start comparison |
| EX02 | Cluster-page replacement discards focused pagination controls. | Exact-event pagination |
| EX03 | Preview lengths are presented as exact cluster and range counts. | Count provenance |
| EX04 | Lane-picker controls ignore rejection at the resource cap. | Checkbox rollback |
| EX05 | Timeline/source/detail entries lack bounded cache ownership across navigation. | Cache retirement |
| EX06 | Brush cancellation restores a captured loading placeholder after its request has finished. | Range-summary authority |
| EX07 | A whole-record UID regex matches references and can hit the cap before the actual source record. | Exact source identity selector |
| EX08 | A hover card's last positioning fallback assumes room to the left and covers its own trigger in narrow viewports. | Constrain the existing scrollable card to free space above/below; reset on reopen |
| EX09 | Fixed-width cluster markers and hover scaling extend across neighboring time centers, so one marker intercepts another's click. | Bound existing glyph footprints by adjacent rendered centers; keep exact identity/time and restore count labels when space permits |
| EX10 | Disconnect before request-body completion escapes the query cancellation scope as an unhandled transport exception. | Translate that known disconnect to the existing cancellation error before provider acquisition |

The main changes reuse existing navigation/request ownership, renderers,
selection resolution, filters and query indexes. Additional logic is limited
to bounded cache retirement, visibility/footprint geometry, and an exact core
source selector where regex matching cannot express record identity. There is
no new plug-in hook, parallel request controller or replacement UI framework.

## Earlier findings

The October 20 frontend findings are covered by
[frontend recovery fixes](frontend-fixes-2026-10-20.md),
[outstanding audit fixes](outstanding-audit-fixes-2026-10-20.md), and
[nine audit repairs](nine-audit-fixes-2026-10-20.md).
Executable identity and search projection/cache follow-ups were implemented in
[identity repair](identity-projection-2026-10-20.md),
[search cache work](search-cache-implementation-2026-10-20.md), and
[validation reuse](validation-projection-2026-10-20.md).
Those historical performance results are baselines, not new measurements.

The separately diagnosed Windows Proactor connection-reset cleanup defect is
an upstream runtime issue; see the reproducible
[runtime investigation](followup-investigation-2026-10-20.md#4-windows-reset-cleanup-remains-a-runtime-issue).
Suppressing its traceback would not complete the interrupted cleanup. This
repair pass does not mislabel that runtime defect as a frontend fix.

## Validation

Parent-run checks:

- `npm --prefix frontend run check`: 506 tests pass, including nested cases.
- Affected source-record, range-summary, normalized-data, revision-query,
  single-node HTTP and author-documentation suites: 95 tests pass.
- Final route identity/direction integration and range-bound suites: 7 tests
  pass, including equivalent aliases and rejection of conflicting identities.
- Node-workspace and frontend Python guards: 75 tests pass. Stale source-text
  expectations were updated to the behavior covered by executable regressions.
- Final author-documentation/example smoke: 18 tests pass (overlaps the 95).
- Cancellation lifecycle: 4 tests pass, including empty/partial request bodies
  on both timeline and density routes, cooperative cancellation and cleanup.
- Conformance inventory, both skill format checks and `git diff --check` pass.

Windows sandbox socket denial prevented local proxy/TestClient startup; the
same checks passed with approved loopback access and a workspace-local temp
directory. No product workaround was introduced. This was a focused repair
validation, not a full repository CI run or completion of the 600-case plan.

### Independent browser replay

The parent used the in-app browser against the unchanged 1M archive on port
8883, with the repaired backend and reloaded frontend assets.

| Repairs | Independently observed result |
| --- | --- |
| SN001–SN005, EX04 | Requested roots retain priority at the lane cap; combined mode discloses sampling; counterpart-layer filtering works; row/layer/native checkbox focus survives; rejected additions return to unchecked. |
| SN008 | Full 0–720 s range returns 1,250,005 events and bounded endpoint facts; an unchanged boundary key retains the completed result. Full-scale service comparison follows below. |
| SN010–SN012 | Correlation disclosure survives reopening; native pagination progresses through all 499 relationships with visible focus, ending on the group summary; Ctrl-click selects and visibly focuses the exact lane, including after None clears all lanes. |
| SN013–SN015 | Invalid `not-a-time` plus Best effort draft retains the applied Strict chip and original basis; empty searches retain the selected kind; repeated Space reaches the native checkbox. |
| MN001–MN005 | Real MPLS handoff disagreement is named correctly; incomplete resolution remains unknown; asymmetric Forward/Return contexts switch correctly; withdrawn history does not invalidate active failover; external destination keeps its logical label. |
| MN006–MN008 | Actual node → fabric round trip restores the latest route seed; End/Left keyboard hop previews track focus; max-hops 1 reports the budget stop. Stationary-pointer interference is covered by the executable handler test. |
| MN009–MN012 | Main/return route-row seeds retain destination identity, synchronize start controls, clear a preceding unknown-destination error, and complete the P1 transit trace without alias conflict. |
| EX02–EX03 | Dense cluster exposes its authoritative 132-event total; exact pagination advances 100 → 132 and places focus on the visible Close control. Preview-versus-exact range counts also have executable coverage. |
| EX08 | On a 592 × 668 viewport, the previous popup covered the jump button; after repair, the same Ctrl-click opens/focuses ETG10, then a reverse jump after None opens only DTE9. |
| EX09 | Before repair with 69 ETG lanes, the center of a 132-event cluster opened its 12-event neighbor. After repair with 21 ETG lanes, 40 unclipped dense marker centers hit their own identities, pointer drill-down opens the expected 21-event cluster, and 100× zoom restores 27 px markers and visible 32-event count labels. |
| EX10 | Rapid lane additions produced an ASGI `ClientDisconnect` traceback before body completion. Direct ASGI regression replay now returns the existing 499 cancellation outcome before acquiring a runtime; this is distinct from the upstream Proactor defect. |

The 499 outcome is the server's cancellation classification; an already
disconnected browser need not receive a response.

SN006/SN007/SN009 and EX05/EX06/EX07 have deterministic production-function or
HTTP regressions for delayed navigation, multi-effect identity, concurrent
selection, cache ownership, canceled loading, and exact source identity. They
are not described here as fresh manually delayed browser reproductions.
Cache checks include visible incident/causal previews and late detached cluster
completion. Navigation checks include wheel input before its scheduled frame,
None/layer/source changes, and a jump's own synchronous viewport move.

SN001's prioritization intentionally changes which endpoints fit in the
100-lane budget. Historical-only endpoints may be omitted and disclosed;
interval history for accepted endpoint pairs remains intact. The displayed
combined count is therefore not expected to equal the old expanded membership.
Very dense marker labels are hidden when they cannot fit; accessible totals
and hover details retain exact counts. Coincident timestamps retain visible
marks and keyboard drill-down, but the footprint correction does not spatially
separate evidence at exactly the same time.

Browser observations are saved in
`.runtime/audit-repairs-2026-10-21/browser-records.json`; the tool transcript
also retains observations made before a browser-automation kernel timeout.
That timeout is not classified as an application latency measurement.
The parent separately reviewed the affected backend changes, and read-only
reviewers checked final request, cache and endpoint ownership paths.

New executable cases are in
`frontend/tests/single_node_audit_recovery.test.mjs`,
`frontend/tests/correlation_list_recovery.test.mjs`,
`frontend/tests/route_audit_regressions.test.mjs`, and
`tests/test_range_summary_bounds.py`; existing route, source-record and
cancellation suites also contain targeted regressions. Browser screenshots
include `resource-jump-fixed.png` and `dense-marker-fixed.png` in the evidence
directory. The live local demo was restarted with the final backend.

### Documentation and skill drift

Both repository skills and the validation map now cover ownership across
components, visible focus, count/provenance distinctions and narrow-screen
hover hit targets. The maintained authoring set, API contract and architecture
describe the exact core source selector and requested-root priority. The demo
README links the exercised checks; parser/example code needs no new hook.
The documented example smoke and conformance inventory were rerun. Skill
format validation passed; this pass does not claim a new blind-model skill trial.

### Full-capture range summary

Fresh-process comparison uses the same 286,496,584-byte generated archive,
PE-A revision `demo/node-a/revision-0001`, Python 3.12 and all 1,250,005 events.
Only the summary service implementation differs: the baseline module is taken
from `112d346`, while the after run imports the changed implementation. Each
process loads the same data, then performs two full-capture queries. Memory is
sampled every 50 ms. CPU is process CPU, including the sampler; neither CPU nor
elapsed time here measures browser rendering. Complete canonical JSON hashes
match for both query results, including all detail, counts and truncation facts.

| Measurement | Before, run 1 / run 2 | After, run 1 / run 2 |
| --- | ---: | ---: |
| Full-range elapsed | 33.582 / 37.244 s | 3.029 / 2.710 s |
| Full-range CPU | 33.063 / 36.266 s | 2.797 / 2.672 s |
| Sampled query peak RSS | 5.301 / 5.303 GiB | 2.428 / 2.429 GiB |
| Loaded RSS before first query | 2.352 GiB | 2.353 GiB |

These are two measurements per version, not confidence intervals. This change
reduces temporary query work and memory, not the loaded dataset size. The
separate prior 40-phase navigation/search benchmark was not rerun for this
repair. A later compatibility guard clamps counts for reversed direct-call
bounds; the HTTP endpoint rejects those bounds, and the measured valid-range
path is unchanged. That guard has its own regression test.

Evidence: `.runtime/audit-repairs-2026-10-21/measure_range.py`,
`baseline_normalized_data.py`, `range-before.json`, `range-after.json`, and
`range-comparison.json`. Both result files include module hashes, exact bounds,
memory counters and complete-result hashes. A separate synthetic query probe
under `.runtime/backend-audit-fixes/` measures CPU, returned counts and temporary
allocations; `tests/test_range_summary_bounds.py` checks projection-call bounds.
Neither substitutes for this full-scale run.
