# Stateful frontend audit — pre-repair execution record

Repairs and validation are recorded in
[the consolidated repair report](../audit-repairs-2026-10-21.md). The original
observations and execution tally below remain unchanged; unexecuted planned
cases have not been reclassified as passing.

Revision: `112d346447316af6ae8f5503c252d5b66d317b07`.
Fixture: existing local 1M demo on port 8883; PE-A has 1,250,005 normalized
events and 7,510 resources. No product code or skills changed.

The plans contain **300 single-node and 300 multi-node route-trace cases**.
Planning does not count as execution. The tally below uses the latest records
present through **2026-10-21 13:32:40.299 UTC**. At that cutoff, the primary
agent had exercised **436 planned cases** through the browser: S001–S090,
the eighteen range cases listed below, all 30 log cases S121–S150,
all 30 correlation cases S151–S180, all 30 topology cases S181–S210,
eighteen resource-table cases S211–S228, and M001–M220. The latest record for
each included case gives these outcomes:

| Executed group | Cases | Pass | Finding reproduced | Inconclusive |
| --- | ---: | ---: | ---: | ---: |
| Single-node planned, S001–S090 plus eighteen range cases and S121–S228 | 216 | 181 | 35 | 0 |
| Multi-node planned, M001–M220 | 220 | 163 | 57 | 0 |
| Single-node expansions, SX001–SX015 | 15 | 0 | 15 | 0 |
| Multi-node expansions, MX001–MX014 | 14 | 2 | 12 | 0 |

The eighteen additional single-node cases are S091/S092/S093, S096/S097/S098,
S101/S102/S103, S106/S107/S108, S111/S112/S113 and S116/S117/S118. The missing IDs within S091–S120
have not been silently counted as passes or replaced by these repetitions.
All 30 log cases S121–S150 and all 30 correlation cases S151–S180
have final records. Conditional empty/short relationship-list branches are
identified below; those passes do not claim pagination was exercised.

The **twenty-seven unique confirmed findings in this matrix** comprise fifteen
single-node findings (SN001–SN015) and twelve multi-node findings (MN001–MN012).
The 119 case records marked finding are not 119 unique bugs. Planned cases total
**344 passes and 92 finding reproductions, with no inconclusive cases**.
The twenty-nine expansion cases add two passes and twenty-seven finding
reproductions; they do not replace planned cases. Across both groups, the
465 distinct executed IDs comprise **346 passes and 119 finding reproductions**.
S011's latest settled two-cycle rerun passes and supersedes its inconclusive record.

The latest completed batch adds S217–S228 and M216–M220: seventeen planned
cases, with no new expansions or unique findings. ETE and DTE resource cases
repeat SN014's hidden active kind, SN015's flat checkbox activation failure and
SN005's bundle focus loss; paging and temporal attribution pass. S220's latest
native-paste/immediate-click execution passes and supersedes its inconclusive
attempt. S226 uses the same rapid method and repeats only SN014. Neither case
establishes an older request in flight or deliberately delayed-response ordering.
The missing-P2-resolution scenarios repeat MN002 while capture-context and
inference retirement checks pass. M220 also repeats MN011 after restoring PE-D.
No new performance finding is established. Earlier batches
retain SN011/SN012's focus-visibility findings, S174's dense Custom repetition
of SN001, S149's pending Add → Hide scope for SN009, and MN008's hop/recursion
scope across eight scenarios.

**SN008** remains repeated full-capture range-summary latency,
including an unchanged-boundary End key that unnecessarily recomputes the result.
S098 observed the panel still loading at 36.207 seconds and complete by 36.639
seconds. These are UI observation bounds, not CPU or HTTP-duration measurements.
S103 also remained loading at 37.829 seconds. See
[the range-summary investigation](full-range-summary-latency.md). S103 repeats
SN008 and MX010 repeats MN007.

The pending-Reveal defect is already finding 1 in
[the preceding exploratory audit](../repeated-cross-component-audit-2026-10-21.md).
It is included in this matrix's twenty-seven, but is not an additional unique bug
across the reports.

The multi-node findings are:

- **MN001, P3:** cross-node handoff mismatch labeled “Layer disagreement,”
  reproduced by M007/M008/M010/M011 and route-table repetitions
  M193/M195/M196/M198. See
  [multi-node findings](multi-node-findings.md).
- **MN002, P2:** incomplete resolution is falsely reported as evidence
  disagreement, reproduced by M016/M017/M018, M058/M059/M060, M160–M165,
  M216–M220, MX002 and MX006. See
  [multi-node findings](multi-node-findings.md).
- **MN003, P2:** changing direction retains the incompatible routing context in
  the asymmetric scenario, reproduced by M027 and MX003. See
  [direction-context investigation](multi-node-direction-context.md).
- **MN004, P2:** known withdrawn history suppresses complete active failover with
  an incomplete/best-effort diagnosis, reproduced by M034/M035/M036, M109/M110/M111 and MX005.
  See [failover-completeness investigation](multi-node-failover-completeness.md).
- **MN005, P2:** logical external-subnet endpoint labels are replaced by the
  attachment router name, even when the explicit prefix remains in the form.
  MX007 repeats the loss in Return, Forward and resubmission; local route
  termination remains correct. See [endpoint-label investigation](multi-node-endpoint-labels.md).
- **MN006, P2:** node links retain an older route query after a new trace is
  submitted, so actual node Back navigation restores the wrong scenario and
  direction. MX009 deliberately reproduces it and verifies recovery after
  refocusing P1. See [return-context investigation](multi-node-return-context.md).
- **MN007, P3:** keyboard scrolling under a stationary pointer replaces the
  focused packet transition's preview and correlated highlight with another
  chip's hover. MX008 and MX010 repeat it and verify pointer-outside controls; packet
  data and pin toggling remain correct. See [packet keyboard/hover investigation](packet-keyboard-hover.md).
- **MN008, P2:** traces stopped by requested hop or recursion limits are explained as
  missing, unresolved or inferred node-local evidence, without the budget-stop
  reason. M157/M166/M172/M175/M178/M181/M184 reproduce the hop case and M170
  the recursion case in Forward and Return; restoring defaults and retrying
  recovers each baseline, including the expected loop scenarios. Retained destination-operation
  text does not establish delivery or an ignored limit. See
  [trace-budget explanation investigation](trace-budget-explanation.md).
- **MN009, P2:** enabled main Forward route-table rows lose their logical
  destination descriptor and submit its ID as a value, producing an unknown
  destination-value error. M187/M190/M192/M199/M208/M210 and MX011 reproduce
  it for service or external-subnet destinations; node-only
  candidates, main Return rows and a manually entered advertised prefix
  execute successfully. See [route-table seed identity investigation](route-table-seed-identity.md).
- **MN010, P2:** row seeding changes trace direction without updating the
  start field's enabled state, usage marker or help. M188/M191 and
  M194/M197/M200/M203/M206/M209 leave it enabled for Return; MX012 leaves it
  disabled for Forward. The traces succeed and
  manual direction changes restore the field. See
  [route-table start-state investigation](route-table-start-state.md).
- **MN011, P3:** replacing a failed route-table seed retains its unqualified
  error beside the new form and seed notice before any new submission.
  MX013 reproduces this with a node-only control candidate and a main Return
  row. M215/M220 extend the same stale-alert problem to successful source-membership
  restoration and reconstruction for PE-A and PE-D: an excluded-source error
  remains before retry. All explicit retries execute and clear the alert;
  M220's intended incomplete baseline remains incomplete. This is stale
  presentation, not rejection of the replacement requests. See
  [trace stale-error investigation](route-table-stale-error.md).
- **MN012, P2:** a traceable P1 transit row seeds the correct P1 start and A/B
  flow fields, but explicit submission rejects equivalent start descriptors.
  M202/M204 and MX014 reproduce it; clearing only the row association while
  preserving all twelve visible values lets the manual Forward trace succeed.
  Main Return execution also passes. See
  [transit-row start investigation](route-table-transit-start.md).

The remaining **164 planned cases** need execution. They include the twelve
held-brush cases whose required gesture is unavailable through the exposed
browser API. The 600-case goal remains active.

## Evidence and counting

- `single-node-plan.json` and `multi-node-plan.json` contain the planned actions.
- `single-node-results.jsonl` and `multi-node-results.jsonl` retain every execution
  record, action, assertion, outcome, note and evidence path. Large top-level
  `dom` and `states` captures are retained in byte-identical local originals at
  `.runtime/audit-repairs-2026-10-21/{single,multi}-node-results.raw.jsonl`;
  each compact record's `raw_record` identifies the original file, line and
  omitted fields. Other recorded observations and request timings remain in
  the published ledgers. Aggregate by the latest record for each ID. Preliminary
  S006, S024, S031, S038, S039, S076, and S079 observations were superseded
  after settled reruns; those preliminary records do not count separately as
  findings or extra cases. S079's completed rerun reproduces the known race.
  S081's preliminary unselected double-click and generic ETG observer were
  superseded by the planned pre-revealed, selected DTE baseline and exact
  canonical observer. M098's initial helper read the wrong candidate attribute;
  all native-keyboard moves were repeated with the actual `data-route-path`.
  S151's provisional finding read pending scope-transition DOM; its final
  settled pointer and keyboard round trips pass and supersede that record.
  S011's latest two settled hide/reselect/reveal cycles resolve its planned
  sequence as a pass; its earlier ambiguous rapid-action attempts do not prove
  a pending-response race. M182's preliminary finding incorrectly required
  chip text to end with Deliver, ignoring the explicit MTU-basis suffix; its
  corrected final record passes against the unchanged baseline.
  M202's source-row check was corrected to the actual P1 owner; that navigation
  passes while the seeded trace rejection remains. MX014's manual hopline
  comparison ignores rendered newlines and passes. S205's `−10m 0s` display
  correctly represents −600 seconds; its preliminary formatting expectation
  was not a product defect.
  S220's final native-paste/immediate-next-tab execution supersedes its earlier
  inconclusive attempt. Initial undelivered actions remain in the saved states
  for attribution. The final pass establishes delivered rapid latest-state
  ownership, not controlled in-flight response ordering.
- M082–M084's preliminary one-hop assertions were invalid: packet Drop stops
  later packet transitions, while the unusable candidate's three-node topology
  remains inspectable with downstream `not_traversed` metadata. Their latest
  records pass the valid packet-stop/no-delivery checks. MX008's earlier
  pin-retention assertion was also superseded: clicking its already pinned
  chip correctly toggled the pin off. Neither correction adds a bug or case.
- Runtime evidence is under `.runtime/audit-600-2026-10-21/single-node/` and
  `.runtime/audit-600-2026-10-21/multi-node/`. These raw observations, screenshots,
  logs and probes remain in the ignored local `.runtime/` directory; links to
  them are local evidence references, not files published with this report.
  The delegated executor's initial
  browser-unavailable event is a setup limitation, not an executed case; the
  primary agent subsequently performed M001–M220 in its browser.
- The lane cases were also chained as stateful sequences. Actual setup and
  actions in the ledger take precedence over a plan's generic reset recipe.
- Browser DOM observations, browser-control timeouts, and synthetic production
  service probes are distinguished below. No new CPU, RSS, or heap measurement
  is claimed. Browser automation elapsed time includes tool overhead.
- S067–S070, S077–S080 and S087–S090 use an isolated localhost proxy on port
  8896 against the same real demo. A controlled 15-second delay holds the real event-log selection request
  before forwarding; it is not a natural-response latency or CPU measurement.
  S067's natural attempt did not prove overlap and is excluded from the race
  conclusion.

## 1. P2 — A crowded lane request can drop the resource being revealed

**S023; browser confirmed and independently reproduced through the production
query service.**

1. At capture End, select `node-a/control-plane/IP_ROUTING/blue` in Resources.
2. Choose Selected + correlated and Separate. The response loads 100 lanes;
   the current-time correlation filter displays 70.
3. Hide blue, reselect its resource row, then Ctrl-click its graph node to
   explicitly reveal it. Repeat the jump after the view settles.
4. The exact blue checkbox becomes checked, and blue remains the selected graph
   identity, but its lane is absent. Only 50 custom lanes are displayed.

The state change establishes that the reveal reached its handler. This is
different from S011's earlier ambiguous pointer delivery, whose final settled
sequence passes. Multiple settled retries
leave the same mismatch. In S024, choosing None and repeating the same jump
successfully produces the blue lane; Reset subsequently restores the 13
representative lanes.

`revision_queries.py` around lines 1917–1957 orders requested IDs before history
roots and reserves up to 50 of 100 slots for relationship expansion. It then
slices the base list. The frontend appends the newly revealed root after the
existing custom IDs. That root can therefore be dropped. Custom mode also hides
expansion-only lanes, explaining why 100 returned lanes produce only 50 visible
ones. Repeating `Set.add` does not promote the already appended root.

Evidence: `S023-missing-root-proof.json`, `S023-retry-state.json`, `S023.json`,
and successful recovery in `S024.json`. The primary agent reran
`S023-core-probe.py`: an appended root was absent on two requests; prepending
the same root made it present. This probe uses the production
`RevisionQueryService.timeline` with synthetic scale data, rather than the
browser's loaded revision.

S174 repeats this finding after the blue root checkbox off/on freezes a dense
Selected + correlated set into Custom membership. The checkbox remains checked
but the blue root disappears. Explicit recovery to a small Custom set allows
the planned standalone/child event and Combined → Separate checks to pass;
that recovery does not make the original dense-set assertion pass.

## 2. P2 — Combined associations ignore the counterpart's disabled layer

**SX004; browser confirmed.**

With blue selected in Combined, disable Data bridge while leaving Control plane
enabled. All **7,589 association segments remain**. Switching to Separate with
the same filters displays only blue, correctly excluding the Data bridge
resources.

`combinedAssociationLane` checks the selected root's layer and explicit resource
hides, but does not filter the counterpart through `activeLayers`. Earlier
root-layer tests S004/S010/S016/S022 passed: disabling the root itself hides the
combined row. This expansion covers the different, missed counterpart case.

Evidence: `SX004-bridge-off.json`, `SX004-separate.json`, and `SX004.json`.

## 3. P2 — Wide combined relationship history bypasses glyph budgets

**SX003; browser DOM confirmed, with repeated browser-control timeouts.**

For blue at the full capture window, Combined reports two physical rows but
renders **7,589 relationship buttons and 15,109 boundary elements**. The timeline
contains **38,342 elements and 7,749 buttons**. The corresponding Separate view
contains 9,259 timeline elements. At 20× zoom, the combined view falls to **99
relationship segments, 50 boundaries, and 723 timeline elements**.

The loaded-lane limit is working: the UI explicitly discloses 100 loaded lanes
and 2,619 omitted related resources. The issue is the number of intervals per
loaded relationship, not an unbounded resource count. `combinedAssociationLane`
in `app.js` around lines 2908–2953 maps every intersecting relationship interval
to a button, child labels, boundaries, and hover bindings. Its three visual
stacking rows do not aggregate those intervals. Existing event and status glyph
budgets do not cover this rendering path.

Repeated layout changes and re-enabling the dense root produced CDP input or
evaluation timeouts. Some actions applied despite the timeout; later DOM reads
verified the resulting state. These are responsiveness observations, **not a
CPU benchmark or a quantified latency regression**. The uncapped interval
rendering and its wide/narrow DOM difference are directly established.

Evidence: `SX003-combined-dom.json`, `SX003-narrow-zoom.json`,
`S021-comparison.json`, `S021-dense-dom.json`, and `SX003.json`.

## 4. P3 — Keyboard activation loses focus on layer filters

**SX001; browser confirmed across all three layer filters and both layouts.**

Focus Data bridge and press Space. The filter changes correctly, but the focused
button is replaced and `document.activeElement` becomes BODY. Repeated keyboard
activation requires finding the control again. The same loss occurs for Control
plane in Combined and Hardware driver activated with Enter. Explicitly
refocusing the controls successfully restores all layers.

An explicit before/after observation records BUTTON / Data bridge before the
key and BODY afterward. `renderLayerToggles` in `app.js` around lines 7780–7787
replaces its own container's `innerHTML` without restoring focus.

Evidence: `SX001-before-after.json`, `SX001-focus.json`, `SX001-combined.json`,
and `SX001.txt`. This is a newly identified defect; no earlier working-version
comparison was performed, so it is not labelled a regression.

## 5. P3 — Resource-table selection and bundle actions lose keyboard focus

**SX002; browser confirmed, expanded from cross-type resource selection.**

Focus the DTE9 row in its flat resource table and press Enter. Selection succeeds,
but focus moves from the canonical row (`TR`, `tabindex=0`) to BODY. The same
post-selection loss was observed while switching ETG0 and DTE9 in S014 and blue
in S020. This interrupts keyboard navigation after each selection.

The row handler invokes `selectResource`, which rebuilds the resource table
without restoring the corresponding focused row. Relevant code is around
`app.js` lines 6095–6103 and 7741–7772. This is distinct from the layer-filter
renderer, although both lose focus through replacement.

Evidence: `SX002-before-after.json`, `SX002.txt`, and S014/S020 observations.
The resource and lane-selection assertions in those cases still pass.

S216 extends the same table-replacement focus loss to ETG bundle disclosure
and inline Details buttons. Their requested changes apply to the exact root or
backup-child instance, but focus becomes BODY; an unrefocused next Enter does
nothing. Explicitly refocusing the replacement control restores operation.
SX015's bundle Timeline checkbox correctly toggles the backup ETE off and on,
with exact lane membership restored, but each render again loses focus. The
second Space requires explicit refocusing. These are SN005 scope extensions,
not additional unique bugs or disclosure-state loss. See
[resource-bundle focus evidence](resource-bundle-focus.md).

S222 repeats Details focus loss on the primary ETE child. S228 repeats it on
the primary branch's next-hop ETG1, whose canonical resource also appears under
the backup branch. The exact branch's relationship facts stay correct, and
explicit refocusing restores close and disclosure operations. Returning to
the original ETE/DTE flat view preserves its requested search and schema.

## 6. P2 — Pending Reveal overrides newer navigation or lane hiding

**S067/S069/S070, S077/S079/S080 and S087/S089/S090; known prior-audit finding
reproduced in this matrix.**

While a real toolbar **Reveal in timeline** selection request is held by the
controlled proxy, a newer Back, pan, or explicit lane-hide action takes effect.
After the older response completes, its continuation overwrites that action.
Back loses its restored viewport and Forward history; pan gains an unwanted
stale reveal history entry; an unchecked hidden lane becomes checked and visible
again. Each variant was repeated, across the route event, ETG create event and
final single-effect DTE event. S070/S080/S090's settled re-hides succeed,
distinguishing the ordering defect from a persistent inability to hide a resource.

S068/S078/S088 are protected controls: an unchanged End interaction during the same
pending selection preserves endpoint cursor ownership and slider focus.
The [detailed navigation note](pending-reveal-navigation.md) records the actual
request/action ordering, saved DOM evidence, source cause and repair boundary.
This is the same issue as finding 1 in the preceding audit and does not increase
the unique bug total across reports or count separately for each operation. The artificial
15-second delay establishes overlap; it does not measure natural performance.

## 7. P2 — A multi-effect reveal leaves its selected target's layer disabled

**S074 / SN007; browser confirmed twice with a manual recovery control.**

Hide ETG0 and disable Data bridge and Hardware driver while its affected
Control plane neighbor remains loaded. Select the ETG0 create event and reveal
it from the +49.0–60.9-second viewport. The viewport moves to +114.0–125.9,
but Data bridge stays disabled, the inspector still identifies ETG0, and focus
stays on the toolbar instead of a target mark. Only the neighbor's effect mark
is visible. Manually enabling Data bridge restores the ETG mark and focus;
Hardware driver remains disabled.

The jump captures the ETG resource before refinement, then recomputes the
affected lane after refinement and uses the neighbor's layer to enable
visibility. Selection and focus still use the original ETG resource. See the
[multi-effect layer investigation](multi-effect-layer-reveal.md) for exact
identities, both browser reproductions, recovery, source cause and screenshot
limits. Generic choice among visible affected lanes is an uncounted policy
ambiguity, not an additional finding.

## 8. P2 — Full-capture range summaries repeatedly take tens of seconds

**SN008; S093/S098, with expansions SX005/SX006.** Selecting the full
0–720-second capture leaves the summary loading even after the log reports all
1,250,005 matching records. In the tighter timed repeat, loading persists at
36.207 seconds and completed facts are observed at 36.639 seconds. Reapplying
the identical selection again stays loading beyond 33.5 seconds. Pressing End
on an end handle already at 720 seconds also replaces completed facts with
loading for more than 30 seconds without changing the range.

Back/Forward remains usable while the summary is pending, and the late result
preserves the viewport. Handle focus, final counts and bounded endpoint-scope
disclosure are correct. This is a summary-computation performance finding;
no whole-page freeze, CPU percentage, heap peak, or exact HTTP latency is claimed.

Source review identifies all-event projection before the 500-detail cap as a
likely cost: the core redacts every selected event and then performs aggregate
passes before returning bounded details. The unchanged-boundary trigger adds
redundant work. See [full evidence, timing limits and source analysis](full-range-summary-latency.md).

## 9. P2 — Concurrent actions cancel each other on an unchanged log selection

**SN009; S125/S131/S149, with expansions SX007/SX008.** After selecting two exact
event glyphs, Mark and Hide them, rebuild the log query, and reselect the same
rows. Rapid Show marks → Remove marker leaves the glyphs hidden after the
review markers are removed. Show alone then restores both glyphs. S125 and
SX007 establish the normalized-event case; S131 repeats it for two unmatched
Non-CTF source records with distinct exact glyphs.

SX008 confirms the inverse command order with CTF source records: rapid Remove
marker → Show marks restores the glyphs but leaves both review markers. Remove
alone recovers. Warmed-selection and serial-action controls pass, including
S137's CTF and S143's mixed-stream workflows. S125's first Remove observation
was pending; its later successful completion is not a separate removal defect.

S149 adds pending Add review marker → Hide marks with an unchanged mixed
normalized/CTF selection. Hide completes but cancels Add; the normalized
marker that remains was created earlier during setup, so this is not a partial
combined Add. The saved disabled marker controls establish that Add was still
pending. Retrying Add alone and serial Show/Remove both pass, including exact
identity preservation through query rebuilding and cleanup.

On a cache miss, each call to `resolveEventLogSelection()` advances the shared
request generation, invalidating the earlier consumer even when the query and
selected rows are unchanged. Actual selection-change invalidation remains
necessary; independent actions on the same selection should both complete.
The browser establishes the final cancellation and recovery states. Both
network response orders are controlled only by the separate production-function
probe, not by the browser observations. See
[selection-action evidence and source diagnosis](selection-action-race.md).

## 10. P3 — Reopening Correlations resets unchanged relationship disclosures

**SN010; SX009, browser confirmed twice.** With ETG0 at capture End, expand
the `owns` edge `node-a/scale-rel-000000000` and collapse its outgoing group.
Collapse the panel, then reopen it with native Enter. The group reopens and
the relationship closes. A second run with `selected_egress`, edge
`node-a/scale-rel-000000003`, and the incoming group collapsed repeats the reset.

The exact root, time, graph scope, four node/edge identities and panel-toggle
focus remain correct. Reopening the panel calls `renderGraph()`, which rebuilds
the relationship list with groups open and details closed. The preservation
logic used by pagination is local to that handler and does not cover this
same-query expansion. See [reproduction, screenshots and source cause](correlation-disclosure-reset.md).

## 11. P3 — Relationship pagination leaves keyboard focus outside the viewport

**SN011; S171 and SX010, browser confirmed.** Blue's incoming relationship list
grows from 30 to 60 with native Enter, then to 90 with native Space. Disclosures
and unique edge identities are preserved, and the replacement Show-more button
owns connected focus, but it moves to approximately 2,051 then 3,755 px in a
720 px viewport. Continuing through all 499 returned edges moves focus to the
incoming summary above the viewport when the final Show-more button disappears.

Tab/Shift+Tab eventually recovers visible focus; immediate recovery samples
were smooth-scroll intermediates, not a keyboard trap. Pagination restores
focus with `preventScroll: true` without ensuring its growing-list destination
is visible. See [pagination evidence and source cause](correlation-pagination-focus.md).

## 12. P2 — Resource jumps leave the focused lane behind sticky controls

**SN012; SX011 expands S173, browser confirmed with two targets.** Incoming
endpoint Ctrl-clicks reach the exact canonical ETE1 primary and ETG1 lanes and
graph roots, preserving cursor and time window. After graph refresh and later
settled reads, their label rectangles remain at approximately 11–71 and
55–115 px, covered by the global header and sticky timeline controls. Hit-tests
identify those overlays. Timeline section navigation plus manual page scrolling
recovers visibility without changing the intended root.

S179's newly added DTE1874 lane stays visibly focused at approximately
345–405 px. The failing targets were already loaded; this contrast does not
establish a universal condition. The jump makes one smooth `scrollIntoView`
call, with no later visibility reconciliation. Initial nested scrolling and
refresh/reflow remain possible contributors. See
[jump visibility evidence and source analysis](jump-lane-visibility.md).

## 13. P2 — Invalid topology controls relabel the retained result's clock policy

**SN013; S184/S190/S196/S202/S208 and SX012, browser confirmed.** With a successful Strict
absolute-time result retained, enter `not-a-time` and select Best effort. The
validation error correctly remains authoritative and the retry button becomes
usable, but the applied **Clock** chip changes to `best_effort`. The retained
basis, clock cards, resources and connectivity remain unchanged. S184/S190
record pending UI overlap at capture start and End; this does not establish
server completion or cancellation timing.

SX012 repeats the inverse policy transition and the invalid positive relative
offset. Its relative input initially reads draft `0` while the applied baseline
is still −5 seconds; `+1` retains that baseline but relabels its clock policy.
S196/S202/S208 repeat the invalid positive-offset transition from correctly
applied relative baselines of 0, −5 and −600 seconds, respectively; the retained
Strict data is mislabeled Best effort while the validation error remains
authoritative. Corrected reconstructions and restoration pass. The renderer falls back to
the current control instead of the policy in the retained result's resolved
basis. See [applied-policy evidence and source diagnosis](topology-applied-policy.md).

## 14. P3 — An empty resource search hides the selected kind tab

**SN014; S211/S214/S217/S223/S226 and SX013, browser confirmed.** With the flat ETG kind
selected, a no-match search removes its tab along with every other flat-kind
tab. The two bundle views remain, but neither represents the active flat kind.
A search matching only NEIGHBOR also hides ETG while showing an unselected
Neighbors tab. The table summary still identifies ETG, and clearing the search
restores the correct selected kind and rows. Explicitly switching to Neighbors
works; its own no-match/clear sequence repeats the presentation failure and
successful recovery. Lane membership remains unchanged.

S214 repeats the missing active tab for an empty EVPN view. Its observed
pre-switch request was not busy, so settled kind/filter ownership passes
without establishing pending-request overlap. Search-filtered kind counts
drive the rendered tab list while the selected kind is correctly retained
internally. Keep that active filter represented when its count is zero. See
[empty-search kind-tab evidence and source diagnosis](resource-kind-empty-search.md).

S217/S223 repeat the empty-search loss for ETE and DTE and verify same-kind
clear-search and canonical-selection recovery. S226 delivers native paste and
an immediate switch from DTE to ETE: the latest ETE query correctly reports no
matches, but its active tab disappears. Clear and return recover both schemas.
This is another SN014 repetition, not evidence of a stale-query race.

## 15. P2 — Space fails to activate a flat resource's Timeline checkbox

**SN015; S213/S219/S225 and SX014, browser confirmed.** Native Space with verified INPUT
focus on a flat ETG Timeline checkbox selects the containing row instead of
toggling the checkbox. The checked value and actual lane membership remain
unchanged, and focus becomes BODY. SX014 repeats the failure from checked and
unchecked ETG states and a checked ETE state. Pointer activation correctly
hides and restores ETG, providing the recovery control. S213's unrefocused
second Space lands on BODY and is not a delivered second checkbox activation.

The flat row's Enter/Space handler intercepts bubbled input events and prevents
native checkbox activation. This activation failure is separate from SN005's
focus-loss consequence. SX015's bundle checkbox provides a passing activation
control because its row handler excludes nested controls, although the
subsequent render still loses focus and requires explicit refocusing. See
[Timeline-checkbox keyboard evidence and source diagnosis](resource-timeline-checkbox-keyboard.md).

S219 repeats the primary ETE failure. S225 repeats it for DTE9 after deliberately
adding that initially unchecked resource as a fourteenth lane. Its first Space
has verified checkbox focus; the second lands on BODY. Table, picker and
timeline agree on the unchanged checked state. Pointer cleanup removes only
the added DTE and restores the original thirteen-resource set.

## Resolved observations and continuation

S011's rapid hide → reselect → Ctrl-click sequence sometimes left ETG1 hidden.
However, other pointer actions during automatic section scrolling changed the
timeline cursor instead of activating the intended control. Visible settled
graph jumps succeeded, and a controlled production-function probe did not
reproduce the proposed ordering failure. The final S011 rerun repeats its
planned settled sequence twice with grounded controls: ordinary resource
selection preserves ETG1's hide, explicit graph Ctrl-click restores and focuses
the target, and unrelated hidden ETG2 stays hidden while cursor and viewport
remain unchanged. S011 now **passes**. The earlier rapid-action attempts remain
unverified and do not add a race finding or extra case.

S025–S030 completed the tail-resource lane sequence: exact picker search,
keyboard toggles, selection changes, correlated layouts, layer disable/restore,
hide/reselect/graph reveal, and None/reveal/Reset. S025's supplemental run records
the exact resource checkbox identity after consecutive Space presses. S028 and
S029 deliberately continued S027's correlated-lane state: their observations
cover that state, rather than the plan's generic representative-lane reset.

S031–S042 exercised All retained sources and Syslog rules: successful additions,
zoom/Fit, malformed and unsupported regex rejection, zero-match recovery,
unmatched filtering, keyboard preset toggles, eight-lane capacity, slot reuse,
and cleanup. Review identified premature post-removal observations and missing
settled Fit/focus evidence. Reruns corrected those records. S031/S032 now record
the full-capture 1,250/1,250 default counts and 313 custom records before removal;
S035/S041 identify the exact preset checkbox across both keyboard rerenders.
S034/S040 inspect rendered individual glyphs and cluster endpoint identities;
they do not claim to have expanded every clustered record.

S043–S060 extend the source-rule sequences to Agent events, Status text, and CTF.
All 18 latest records pass: additions and settled zoom/Fit refreshes, unsupported
and malformed regex recovery, honest zero-match lanes, unmatched filtering,
keyboard preset focus, eight-lane capacity, slot reuse, and cleanup. The
unmatched checks inspect rendered individual marks and cluster endpoint
metadata; they do not claim to have expanded every hidden record.

S061–S066 pass exact normalized-event navigation outside the current viewport:
timestamp double-click, Ctrl+Enter, three settled toolbar reveals, restoration
of only the required layer, timeline → normalized-log → timeline keyboard
round trips, and three Back/Forward viewport cycles. The selected event UID,
canonical lane and settled focus were checked independently of the retained
selection range. Missed pointer delivery during scrolling was retried against
grounded controls, not counted as a product failure. S067–S070 then test pending
selection ownership under controlled delay: Back, pan and lane hide reproduce
the known issue, while unchanged End preserves the newer cursor interaction.

S071–S076 repeat those settled navigation operations with the multi-effect ETG0
create event. Double-click, Ctrl+Enter/Escape, three toolbar reveals, exact-mark
context-menu reverse reveal and three native-keyboard Back/Forward cycles pass.
S074 confirms the target/layer mismatch above. A preliminary S076 pointer
sequence did not establish settled one-step history transitions; its latest
record supersedes that observation with six verified native keyboard moves.
Browser-control delays are recorded separately and do not establish a new CPU
or responsiveness regression.

S077–S090 add eight passing records and six related finding reproductions.
The ETG pending Back/pan/hide sequences S077/S079/S080 reproduce finding 6;
S078's unchanged-End control passes. S081–S086 then pass the settled navigation
sequence for final DTE event `node-a/scale-event-01249999`: double-click,
Ctrl+Enter/Escape, three toolbar reveals without duplicate lanes, restoration
of only the required layer, reverse-log/keyboard return and three Back/Forward
cycles. S084's single-effect layer restoration passes, distinguishing it from
S074's multi-effect target-layer error. S085 uses the focused log UID, inspector
and exact timeline mark as identity evidence; reverse navigation does not
require a retained multiselect row set. S087/S089/S090 reproduce the same
pending ownership defect on that DTE resource, while S088 preserves the newer
unchanged-End intent. Both DTE hide repeats and both settled re-hides are saved.
The detailed navigation note preserves S079's early-read correction and the
S090 screenshot limit: its post-response popup obscures the checkbox, whose
checked state is established by the exact DOM observation.

M001–M030 cover the first ten route scenarios in Both, Forward only, and Return
only modes, including repeated submissions and direction round trips. Healthy
primary/standby and ECMP paths, cross-node handoffs, genuine control/forwarding
disagreement, missing resolution, transit observation, asymmetric context, and
one-way drop cases produced three unique findings summarized above. MX001
verified canonical member/revision selection for hop clicks; malformed legacy
hop metadata remains an uncounted concern. MX002 and MX003 expanded MN002 and
MN003. MX004 confirmed that selecting an inferred best-effort alternative does
not erase the observed return drop, and Strict restoration removes that
alternative. Hidden previous-result descendants are excluded from current
result assertions, including the M027/MX003 validation errors.

M031–M033 pass EVPN multihoming all-active in Both, Forward only and Return only
modes: two resolved active ECMP members remain distinct, without a singular
primary, across direction changes and repeated submissions. PE-B and PE-E are
declared attachments of the service endpoint; the differing egresses are not a
demonstrated routing defect. The UI's service-versus-router endpoint label is
linked scope for MN005, rather than a separately expanded browser finding.
M034–M036 and MX005 reproduce MN004:
the active failover path and withdrawn history remain independently selectable,
but aggregate outcome classification treats the retained dead candidate as
uncertain active forwarding. The dedicated note includes the saved screenshot
and distinguishes browser evidence from its synthetic classifier probe.

M037–M057 pass stale-FIB versus control-plane alternatives, SRv6 ECMP, recursive
static resolution, recursive cycles, cross-node loops, split-horizon policy
blocks and local external-subnet termination in Both/Forward/Return modes.
Repeated node occurrences and loop-closing explanations remain inspectable;
policy blocks are not confused with consistency findings. M058–M060 and MX006
reproduce MN002 for missing intermediate P2 resolution, including Strict → Best
effort → Strict recovery. MX007 expands the endpoint-label concern: the form
retains explicit `203.0.113.0/24`, but goals, direction tabs and comparison all
replace that endpoint with PE-E. This is MN005; reachability itself remains
correct.

M061–M090 pass ten packet scenarios in Both, Forward only and Return only
modes, with direction round trips and repeated submissions. The checks cover
native IPv4, incomplete packet capture, SR-MPLS push/swap/PHP, L3VPN label
lifetime, direction-specific SRv6 SID lists, IPv6-over-IPv4 wrappers, nested
VPN stacks, MTU drop, MTU fit and exact equality. Pinned details preserve
directional endpoints and declared layer order; a seven-layer nested stack
remains available despite its short chip summary. Direction changes and
resubmission clear old packet pins. Incomplete capture remains explicitly
uncertain through final delivery without inventing a route inconsistency.

M082–M084 establish one source-node packet Drop, zero active delivery and an
exact ten-byte excess over the comparable MTU. The core deliberately retains
the full unusable route candidate and marks its suffix `not_traversed`; three
displayed candidate nodes are not evidence of packet forwarding after Drop.
The preliminary one-hop expectation was corrected, not counted as a product
failure. Missing explicit “not traversed” wording beside the generic candidate
resolution text remains an uncounted presentation concern; the overall
unusable/drop diagnosis is clear. M085–M090 verify recovery to fit and exact
1500-byte equality without retaining the earlier Drop outcome.

M091–M099 all pass. M091–M093 verify that incomparable packet-size and MTU
bases remain explicitly unknown while three transitions deliver with complete
continuity; no stale fits/exceeds/drop conclusion survives. M094–M096 exercise
the observed default of the forced-steering scenario, with four transitions,
label push/swap/PHP and no counterfactual provenance. They do not claim that
the nondefault forced profile was selected. Direction round trips and repeat
submissions preserve the current packet evidence and clear old pins.
M097–M099 test primary/standby candidate inspection: All paths and Clear hide
selected detail without changing the outcome; the inactive standby remains
inspectable; Home/End/Up/Down retain actual candidate focus; explicit selections
are remembered independently per direction until All paths clears both.
The previous scenario's packet inspector does not remain visible.

MX008 expands packet interaction beyond those passing data checks. With the
pointer stationary over the nested-VPN rail, keyboard End focuses delivery
but scrolling puts the PHP chip under the pointer; its preview and highlight
replace the keyboard destination. This is MN007. A pointer-outside control
follows keyboard focus correctly, and Escape/Close restore the trigger.
Pinned detail is independently correct. The corrected pin-toggle observation
and the screenshot's focus-evidence limit are preserved in the dedicated note.

MX009 confirms MN006 through a deliberate round trip after a completed
native-IP Forward trace: the existing P1 links still encode an older MPLS
Both query, and actual Back restores that old configuration. Refocusing P1
refreshes the hrefs; the next actual round trip preserves native IP Forward.
Return-page evidence establishes restored controls, not an already completed
returned trace. The first incidental node opening is discovery context only,
and the hardcoded `#fabric` fragment is not a second finding.

A focused ETG1874 graph also showed three resources and three relationships
beside a 500-resource truncation warning. The separate
[graph-scope investigation](graph-scope-investigation.md) explains the wider
three-hop query behind that warning. Its synthetic production-service probe
found complete direct relationships. Record this as a scope/copy and avoidable
query-work concern, not demonstrated focused-data loss or an extra confirmed
functional bug. Live cost and broader cases remain unmeasured.

M100–M120 add eighteen passes and three repetitions of MN004. ECMP, EVPN,
stale-FIB and SRv6 candidate selection, keyboard focus, direction memory, and
All-paths clearing behave correctly. M109–M111 retain the known incorrect
aggregate incompleteness caused by withdrawn history. M118 explicitly forces
the alternate P2 packet path and restores observed forwarding, verifying both
packet-step replacement and removal of counterfactual pin/provenance.

All six apply/clear/invalid-input/recovery range cases pass, as do all six
zoom/Fit/Back/Forward/clear cases. All six handle-key cases now pass their
functional assertions. S093, S098 and S103 additionally reproduce SN008's
latency. Narrow selections can correctly retain the same bound when an inward
key would violate the minimum span; a passing no-op is not evidence that both
handles moved. S111/S116 preliminary records read
loading placeholders because the audit wait returned too early; their complete
settled reruns supersede those records and pass. S093 was reclassified from a
functional pass after SN008 was confirmed with timed repetitions. Neither
correction adds an unrelated bug. S108, S113 and S118 first timed full-result
checks were complete at 55.423, 42.108 and 45.454 seconds respectively; those
are upper bounds, not measured computation durations or separate latency bugs.

M121–M150 pass hover/pin/Escape, keyboard End/Home/Left/Enter with Return
cleanup, and exact resolution-step hover followed by All paths/Focused path
and retrace across ten packet fixtures. They cover native IP, incomplete
capture, MPLS, L3VPN, SRv6, IPv6-over-IPv4, nested VPN and all three MTU cases.
The one-chip Drop legitimately retains the same chip for all traversal keys;
fit and exact-limit packets recover to delivery without inheriting Drop.
Successful retrace means the current request settled, not that an incomplete
capture became complete or that a Drop became reachable.

MX010 repeats MN007 with a clean click-first → Escape → End sequence. The
keyboard focuses delivery while the stationary pointer previews PHP. Enter
pins delivery correctly and the pointer-outside control previews delivery.
See [the updated packet interaction report](packet-keyboard-hover.md).

Pointer-control evidence was strengthened during this batch. A zero-distance
scroll does not reliably move the pointer and is no longer accepted as proof
of hover delivery. Early packet cases were rerun; latest C records explicitly
verify the exact step's `:hover`, and keyboard controls verify that no packet
chip is hovered. Neutral-margin drags can position the pointer without clicking
a packet; their incidental browser text selection is not application state.
The clean MX010 screenshot uses ordinary click/Escape/End and supersedes the
initial screenshot with text selection. A first packet clipped by its rail's
horizontal scroll was revealed before hover; failed pointer placement alone
was not counted as a product defect.

S121/S122/S123/S124/S126 pass normalized-log keyboard focus, exact inspector
identity, batch clearing/reselection, native Shift/Ctrl selection, End/Home
navigation across the 1,250,005-record population, search recovery and period
grouping. Modifier selection follows 1 → 4 → 3 → 4 → 2 with the correct anchor.
End reaches logical index 1,250,004, then Up/Up/Home/Down reaches
1,250,003/1,250,002/0/1 without refocusing the row between keys.

S123 established a new query but its first End observation was already
complete; no cold-request duration is claimed. S124's immediate error→empty
edit exercises debounce recovery, not a proven overlapping-response race.
S126 reads zero selected and 1,250,005 Other records for 50–60 seconds, then
10,002 selected for 120–121 seconds, and restores the full Visible stream.
The latter period's Other-records header was outside the rendered first page;
its inferred 1,240,003 count is not asserted as a direct observation. An actual
normalized-checkbox off/on round trip restores the original population.
S125 is now complete and reproduces SN009. The exact +30/+120-second event
glyphs were made visible with cursor +30, zoom 2 and Center before Mark/Hide.
After the query rebuild, rapid Show/Remove left both rows hidden with zero
review markers; settled Remove succeeded, and Show alone restored the glyphs.
SX007 repeats the cold-selection failure and verifies a warmed-selection control.

S127–S144 complete the remaining log combinations across Non-CTF, CTF and mixed
normalized/Non-CTF streams. Keyboard identity, Shift/Ctrl selection, End/Home
navigation, search recovery and stream restoration pass. S129/S135 did not
observe a cold page pending, and immediate search edits exercise debounce
recovery rather than proven response overlap. S141 did observe Loading history
page; its final connected focus reached logical index 1,252,504 and subsequent
Up/Up/Home/Down moves passed. Temporary BODY focus while that page was pending
is not claimed as a settled focus failure.

S131 extends SN009 to two exact unmatched Non-CTF source glyphs at +120.100 and
+120.200 seconds. S137's serial CTF Show → wait for glyphs → Remove and S143's
serial mixed normalized/source workflow pass. SX008 separately confirms the
inverse rapid-action failure on CTF sources. These source identities are not
matched-source aliases of normalized events.

The source-only period checks partition +120–121 seconds into 19 selected and
2,481 Other Non-CTF records, and 20 selected and 2,480 Other CTF records. S144
explicitly scrolls to the virtual group boundary and observes 10,021 selected
plus 1,242,484 Other mixed records. Its grouped End restores connected final-row
focus, and clearing the range and toggling both stream checkboxes restores the
1,252,505-record population. The Other count is directly observed here, unlike
S126's earlier off-page header.

S145–S150 complete all-three-stream log coverage at 1,255,005 matching records.
Keyboard inspection, exact selection transitions, search recovery and period
grouping pass. S147 observes End's Loading history page before connected focus
reaches logical index 1,255,004; Home returns to the cached first page. S148's
immediate error → empty edit remains a debounce check, not proven response
overlap. S149 reproduces SN009 through pending Add → Hide, then passes serial
retry, filter reconstruction, Show and Remove cleanup. S150 reads the Other
group at the actual virtual-scroll boundary and restores the full population
after a CTF checkbox off/on round trip. No untimed-record or full-range timing
coverage is claimed by these log cases.

S151–S161 pass the completed correlation cases for ETG0 and ETG1: settled
pointer/keyboard scope round trips with cap disclosures, collapse while
changing time, plain node pin/Escape inspection, and intentional endpoint jumps.
S151's initial pending read was superseded by its settled pass. S153 has zero
incoming relationships, so no incoming detail or Show-more operation is
available. S159 opens an exact incoming relationship in a complete two-item
list; pagination is likewise unavailable. Those allowed conditional branches
do not establish paging behavior.

S155's outgoing jump and S161's incoming jump both reach the correct canonical
primary ETE lane and graph root while preserving the cursor and viewport. The
incoming button correctly uses the declared source endpoint. S156 explicitly
freezes lane membership through a checkbox off/on round trip before activating
the duplicate child event. Grounded pointer and native Enter activation preserve
the exact event/tree identity, focus and popup after detail refresh and after
Combined → Separate. Initial undelivered/clipped-control attempts are setup
limitations, not product findings. SX009 separately confirms SN010's
same-query collapse/expand disclosure reset; that is different from the
passing time-change panel cases.

S162–S180 complete the remaining correlation combinations for ETG1, DTE9,
blue and ETG1874. Scope round trips preserve root/time with explicit server
and canvas caps; collapse/Home/expand/End respects actual root existence;
plain-node pins and Escape preserve selection. S165's empty incoming list and
S177's complete one-item list legitimately omit pagination. S171/SX010 exercise
the dense branch through all 499 unique returned edges, preserving disclosures
while reproducing SN011's offscreen focus. Those pages do not establish that
the capped response contains every relationship in the dataset.

S162/S168/S180 preserve exact child tree keys, event UIDs and popup identity
across pointer/native Enter activation and Combined → Separate. S168 narrows
the viewport to expose an exact early ETG9 event and adds its standalone lane
before comparing duplicate instances; the early historical relation correctly
differs from later ETG10. S174 reproduces SN001's dense Custom cap, then passes
the duplicate/layout checks after a recorded small-set recovery. Clipped or
undelivered initial pointer attempts are excluded; a browser-control timeout
followed by confirmed delivered activation is not CPU evidence.

S167/S173/S179 preserve exact endpoint identity, focused canonical lane and
time/window. SX011 separately expands S173 with the visibility assertion that
confirms SN012; S173's original identity assertions remain passing. S179's
newly added target provides the passing visibility control described above.

M151–M156 pass the remaining packet hover, pin, keyboard, direction cleanup and
All paths/Focused path/retrace combinations. The explicit forced P2 path in
M154 and ingress/transit wrapper profiles in M155/M156 retain their declared
counterfactual provenance and exact packet-layer effects. M157–M168 then cover
hop limits, zero recursion, native invalid-budget validation and restoration
across four route scenarios. M160–M165 repeat MN002; M157 and M166 establish
MN008 in Forward and Return on two otherwise reachable baselines. All budget
restore/retry controls pass: default limits return, unrelated inputs remain,
the old result is invalidated until retry, and the explicit retry restores the
baseline outcome. Native-invalid inputs are blocked by form validation; a
blank application error is not a failed validation in those cases.

M169–M171 complete the budget combinations for recursive-resolution-cycle.
At maximum hops 1, cycle detection legitimately retains the recursive-cycle
reason in both directions. Maximum recursion 0 stops earlier and removes the
later loop, but M170 reproduces MN008 because the visible explanation still
attributes incompleteness to missing evidence rather than the recursion limit.
Native-invalid budgets are rejected; default restoration and explicit retry
return the original loop outcome. A successful restore is not a claim that
this deliberately cyclic fixture becomes reachable.

M172–M186 extend budget/recovery coverage to cross-node-forwarding-loop,
native IP, nested VPN, incomparable MTU and the forced-steering scenario under
its retained observed-steering setting. Hop-limit cases M172/M175/M178/M181/M184
repeat MN008 in both directions. Packet prefixes correctly stop without
delivery; cross-node loop detection is preempted by the earlier hop stop.
All default-limit restoration and explicit retry controls recover their
respective baseline outcomes. Zero recursion leaves these nonrecursive paths
and the nonconsecutive cross-node loop unchanged; nested packet wrappers are
not resolver recursion. Native invalid-budget checks pass in all five groups.

M182's final corrected record passes: the delivery chip also displays
**MTU BASIS DIFFERS**, so the preliminary string-suffix assertion was invalid.
The incomparable-size disclosure remains explicit, not a known MTU failure.
M178's ambiguous initial navigation attempt is excluded; its accepted case
was rerun from the visible form. The forced-steering scenario name in
M184–M186 does not imply that forced steering was selected.

S181–S192 exercise single-node topology reconstruction at both capture
boundaries: repeated requests, association/underlay projection changes,
Strict/Best effort round trips, invalid-time recovery, pinned time versus
Follow timeline selection, canonical resource jumps, and selected ranges that
do not change the pinned reconstruction basis. S184/S190 repeat SN013, while
the other ten cases pass their recorded assertions. S182's capture-start
underlay has only explicitly undirected/unknown static links, so its directed
substep is unavailable; S188 at End checks an actual directed relationship's
source, target and arrow. The bounded resource list and empty early
connectivity are disclosed, not treated as missing-data defects.

SX012 expands SN013 without a pending request, covering both policy directions
and both time validators. S186/S192's rapid projection sequence is judged by
the final applied projection and basis, not inferred network cancellation.
S192's initial browser observation timeout was superseded by a repeated,
settled sequence; it is not a product-latency finding.

M187–M192 exercise route-table filters, main and retained-candidate seeds,
Forward/Return replacement, explicit trace submission and **Show source row**
for `single-active-primary` and `all-active-ecmp`. Main Forward seeds in
M187/M190/M192 reproduce MN009. MX011 confirms a successful exact standby
candidate, the repeated main-row failure, and manual advertised-prefix
recovery. M189 passes zero-match recovery and exact candidate focus while
retaining the available-alternative qualification. M192's empty state and
filter clearing also pass; its later seeded trace fails independently.

Main Return traces in M188/M191 retain the original source/destination form
values, execute in the correct direction and focus their exact rows, providing
passing MN009 controls. Their stale enabled Forward-start field reproduces
MN010. MX012 confirms the inverse disabled Forward-start state after a Return
baseline, with successful trace execution and manual direction-toggle recovery.
Source-row navigation passes throughout. Hidden old result text is not counted
as a new trace, and horizontal scrolling that exposes a table column is not an
additional defect.

S193–S210 complete the topology cases at relative watermark offsets 0, −5 and
−600 seconds. Each group covers repeated reconstruction, association/underlay
replacement, Strict/Best effort round trips, invalid positive-offset recovery,
absolute pinning versus Follow timeline, canonical resource navigation, and a
120–121-second selection without changing the applied relative basis.
S196/S202/S208 repeat SN013; the other fifteen cases pass their recorded
assertions. S194/S200 inspect actual directed underlay relationships, while
S206 has only explicitly undirected/inferred static links at its earlier basis;
that case does not claim the directed substep was exercised. Observation
timeouts in S193/S197/S198 and an offscreen target in S206 were resolved by
reading the delivered state or exposing the actual target, not counted as
product latency. Final projection and capture-vector checks do not establish
network completion order or cancellation.

M193–M210 complete the route-table sequences across MPLS and VXLAN handoff
mismatches, cross-layer disagreement, a transit starting point, asymmetric
SRv6/MPLS routing and an external subnet. M193/M195/M196/M198 preserve the
actual cross-node diagnostic but repeat MN001's incorrect summary label.
M199 repeats MN009 for the cross-layer main Forward seed; M201's retained
control candidate succeeds after empty-search recovery, remains explicitly
not installed, and focuses its exact source row. Cross-layer disagreement is
expected evidence in this fixture, not an additional defect.

M202/M204 and MX014 establish MN012: the exact P1-owned Forward seed retains
the intended P1 start and A/B flow fields but fails with a start-selector
conflict, including after zero-match recovery. Re-entering the same destination
clears the row association without changing any of the twelve recorded visible
values; the manual Forward request then succeeds P1 → B with original flow
A → B. M203's main Return row succeeds B → P2 → A without revisiting P1.
Its enabled start field is the separate MN010 repetition, not a failed trace.

M205/M207 pass the asymmetric Forward seed and its zero-match recovery in the
blue SRv6 context. M206's Return seed executes C → P2 → P1 → A in the default
MPLS context, providing a passing row-seeding differential for MN003's manual
direction/context problem; only MN010's start-control state fails. M208/M210
repeat MN009 for `destination:eta-external-subnet`, including empty-search
recovery. M209's node-only Return query succeeds E → P1 → A and repeats only
MN010; this does not claim the logical external endpoint label was restored.
The Return traces in M194/M197/M200 also execute and focus the correct rows
while repeating MN010. Source-row navigation and the recorded filter recovery
checks pass throughout this batch.

MX013 establishes MN011 separately from MN009: after a failed service-ID
request, replacing the main seed with a node-only control candidate or main
Return row retains the old unqualified error beside the new parameters before
submission. Both explicit replacement traces succeed and clear that error.
The candidate keeps its control-plane-only/not-installed qualification, and
the Return retains the expected cross-layer evidence. This is not an
asynchronous response-order claim or rejection of either replacement request.

S211–S216 begin resource-table coverage at capture End. S211/S214 and SX013
establish and repeat SN014's hidden active kind; S213/SX014 establish SN015's
flat checkbox activation failure. S212 passes ETG pagination through offsets
500 and 1000 and back to 500, then search/clear reset to the first valid page.
A complete single-page search omits pagination rather than showing disabled
buttons; that branch is recorded explicitly. S215 passes native Home/End
temporal attribution: pending rows retain the old shown time while the new
requested time is identified, early catalog rows honestly say Exists=no, and
End restores capture state with the exact resource and search preserved.

S216 and SX015 extend SN005 to bundle disclosure, inline Details and Timeline
checkbox focus. Expansion maps, exact backup-child facts and lane visibility
changes pass. Native bundle checkbox activation works with explicit refocusing
between keys, distinguishing it from SN015's flat-table interception. S214's
pre-tab `busy=false` observation does not establish overlap with an older
resource request; its passing ownership checks are sequential, and its finding
is SN014 only. Locator timeouts and observation delays add no performance claim.

M211–M215 cover the primary/standby scenario across relative time, independent
clock and missing-hop policies, reconstruction slider boundaries and source
membership. M211/M212 apply new −420/Strict and −270/Best effort clock contexts
and route-table contexts, retire the old trace after reconstruction settles,
and explicitly trace both directions with observed primary/standby qualification.
Old trace content during the pending reconstruction remains attributed by the
applied-time banner and disabled submit; this observation is not a stale
publication finding. M213's missing-hop Best effort/Strict round trip changes
neither the fabric context nor the complete scenario's observed paths, and each
edit invalidates the current result before retry.

M214 passes native slider Home to the observed −720-second history boundary
and End back to latest. The earliest trace owns its incomplete evidence;
the latest retry restores both observed primary paths and eligible standby.
The slider is disabled during reconstruction and is explicitly refocused for
End, so uninterrupted keyboard-focus retention is not claimed. M215 correctly
rejects PE-A outside the reconstructed nine-device scope, restores the original
ten-device context, and successfully retraces both directions. The obsolete
excluded-source alert persists between successful reconstruction and retry,
extending MN011; retry clears it. A selector collision between the policy SELECT
and an SVG MARKER in M213 was resolved with the actual SELECT and adds no
user-visible defect.

S217–S228 extend resource-table coverage to ETE and DTE. S217/S223 repeat
SN014, with clear-search recovery to the first 500 of 2,625 ETEs or 1,875 DTEs
and canonical row selection verified. S218/S224 pass next-page offsets 500
and 1000, exact Previous-page identity restoration, and search/clear reset to
the first valid page. S221/S227 pass Home/End shown-time versus requested-time
attribution, preserving kind and search while reporting early resources as
absent and restoring their capture-time facts at End. Catalog rows need not
disappear merely because the selected time precedes their existence.

S219/S225 repeat SN015's native Space interception and overlapping focus loss;
unrefocused second keys are not treated as checkbox activations. The ETE lane
set remains unchanged; DTE setup adds one lane and pointer cleanup removes
only that addition. S222/S228 repeat SN005 on the primary ETE Details control
and the primary branch's next-hop instance. Instance-specific relationship
facts and expansion maps remain correct, while uninterrupted keyboard use
fails. Refocused controls and return to the original flat view recover.

S220's accepted rerun uses native paste followed immediately by a grounded
native click on the next kind. The matching ETG table owns the settled rows,
descriptors and summary; clearing and returning restores coherent ETE state.
This pass supersedes the earlier inconclusive attempt. S226 delivers the same
method from DTE to ETE and correctly reaches an empty latest-kind result,
repeating only SN014's missing active tab. Neither sequence observes internal
in-flight request state or deliberately delays an old response. They establish
delivered rapid latest-state ownership within those observations, not a
controlled concurrency test. Initial undelivered attempts and locator timeouts
are excluded from product-failure or latency conclusions.

M216–M220 cover `incomplete-intermediate-resolution` under the same time,
policy, slider and membership operations. M216/M217 apply −420/Strict and
−270/Best effort clock contexts, retire prior traces, and preserve qualified
missing-P2 evidence in both directions. Relaxing clock policy alone does not
authorize a missing-hop bridge. M218's Best effort missing-hop trace explicitly
qualifies the inferred continuation and provenance; its Strict retry removes
that continuation and restores unresolved inactive paths without changing the
fabric context. M219's native Home/End reconstructions and latest retry keep
correct time ownership. All four repeat MN002's false disagreement wording;
these repetitions do not imply failed context or inference retirement.

M220 removes the actual source PE-D and correctly rejects it outside the
applied nine-device scope. Restoring PE-D returns the original ten-device
context, but the obsolete excluded-source alert remains until explicit retry,
repeating MN011. Retry clears that alert and restores the intended incomplete
paths in both directions, where MN002 also repeats. Successful request recovery
does not mean the missing resolution becomes reachable. This case counts once
as a finding reproduction even though it demonstrates two existing findings.

Several dynamic-row locator evaluations returned detached prior rows with zero
rectangles, while a fresh document query showed the connected current row.
Native clicks used the current timestamp-cell geometry. Input-dispatch timeouts
were checked for delivered effects before proceeding; none alone is classified
as a product bug or a CPU measurement.

An incomplete packet's local input boundary can correctly say “Continuity
validated” while its after-snapshot and whole-trace continuity remain
incomplete. Source review confirms those separate scopes. More precise wording
is an uncounted presentation concern, not a new continuity defect.

The current browser API exposes atomic drag and timed click but no independent
held-pointer movement operation. A timed-click experiment for S104 queued its
move and Escape until after release, so it did not deliver the required gesture.
Its progress file is a capability diagnostic, not a completed case or a product
failure. The twelve D/E brush-cancel sequences in S091–S120 remain unexecuted;
an automatically released drag followed by Escape is not a substitute.

Some browser-control calls timed out despite a matching element; actual effects
were checked before retrying. Offscreen picker controls required keyboard Tab
navigation in several cases. These control-tool failures alone are not product
failures. The original user tab was not changed; testing used separate audit tabs.
The last planned single-node observation, S228, returns to the flat DTE view at
capture End with search `dte-000009`, its exact requested row and the original
13 resource lanes plus 2 logs. The checkpoint confirms DTE9 remains selected
while its lane is hidden after pointer cleanup, with the full window, no range,
all layers and Separate layout. The last planned multi-node case, M220, ends
with an executed `incomplete-intermediate-resolution` Both trace at applied
relative 0 / Strict clock and missing-hop policy, all ten devices, and Return
displayed. The excluded-source error is cleared; the visible path remains
intentionally incomplete. The checkpoint retains node A's table filter and
records no seed or packet pin. Later setup or cleanup does not add executed
case IDs.
No delay proxy was launched in this batch.

The S108 full-range summary and M144 route retrace were simultaneously pending,
then both completed. Existing access logs do not contain request durations;
29–32-second multi-action tool batches cannot be attributed to product latency.
No CPU, RSS, heap or request-level benchmark was performed.

Next: proceed through S229 onward and M221 onward, and resolve the held-brush
input coverage when the required gesture is available. Preserve the complete
300-case scope per plan. There are 164 planned cases still unexecuted:
S229–S300, M221–M300 and the twelve held-brush cases within S091–S120.

## Documentation stewardship

Plugin-documentation drift check completed. This change adds audit plans and
evidence only; it changes no plugin API, contract, example, or author command.
No authoring-material or skill update is required. Existing frontend test results
on this unchanged product revision were not rerun for an audit-only modification.
