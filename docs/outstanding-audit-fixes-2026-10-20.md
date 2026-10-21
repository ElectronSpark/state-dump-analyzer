# Outstanding frontend audit fixes — 2026-10-20

The findings from the [lane/jump audit](lane-jump-audit-2026-10-20.md),
[extended lane audit](lane-sequences-audit-2026-10-20.md), and
[other-sections audit](other-sections-audit-2026-10-20.md) are fixed in the
working tree. Earlier frontend fixes and unrelated pending backend work were
preserved. This task did not commit or push changes.

## Fixes and independent browser replay

The parent replayed the affected interactions in the existing in-app browser
on `http://127.0.0.1:8883`, using PE-A with **1,250,005 normalized events and
7,510 resources**, plus the Fabric workspace. Local evidence is saved under
`.runtime/audit-fixes-final-2026-10-20/`.

| Finding | Result and evidence |
| --- | --- |
| Selected mode revives old custom lanes when choosing an unloaded resource | Preserves the preset and queries its new target. Selecting `etg-001874` settled at one resource lane. `selected-preset-new-resource.txt`. |
| Lane-picker checkbox loses focus | Restores the same resource control after immediate and delayed rerenders. Space toggled `etg-001870` and focus survived the response. `lane-picker-focus-fixed.json`, `lane-picker-focus-settled-fixed.json`. |
| Combined layout ignores hidden layers | Both the selected root and its association lane respect layer visibility. Hiding Data bridge produced zero resource lanes. `combined-hidden-layer-fixed.txt`. |
| Old asynchronous jumps override later selection or clear | Navigation intent guards payload acceptance, continuations and deferred focus; reset invalidates it too. Composed production-function tests cover exact races; ordinary selection/reveal and window refinement were also replayed in the browser. |
| Retained-source lookup throws on normalized lanes without clusters | Lookup accepts marks-only normalized lanes. Unmatched source reveal works; an absent matched source creates a temporary jump lane. `source-record-reveal-fixed.json`, `source-missing-lane-fixed.json`. |
| Duplicate tree occurrence focuses or anchors a popup on another occurrence | Focus descriptors and hover identities include the tree instance. Keyboard create-event and pointer failover-event selection stayed on the expanded `owns` child. `duplicate-child-keyboard-fixed.json`, `duplicate-child-pointer-fixed.json`. |
| Virtual-log Home/End loses focus and uncached keyboard targets are missed | Keyboard destinations survive page loading and are consumed after restoration. End focused normalized row index 1,250,004; ArrowUp continued to the preceding row, a subsequent mouse selection retained its own target, and Home focused the first event. Source-log End/Home also worked. `normalized-million-end-focus-fixed.json`, `normalized-million-home-focus-fixed.json`, `source-log-end-focus-fixed.json`. |
| Old topology results erase newer invalid-input feedback | New input invalidates response authority before validation. The invalid timestamp error and enabled submit control survived the earlier request; the previously applied basis stayed unchanged. `topology-invalid-pending-fixed.txt`, `topology-invalid-settled-fixed.txt`. |
| Inferred directed edges lose arrows and display Unknown relationship | Explicit direction is preserved; inference labels/rule IDs are presented without treating them as registered relationship types. Browser showed an ETE-to-VI arrow and `relationship:egresses_via inferred`. `directed-inference-fixed.json`. |
| Dashboard collapse/expand/reorder loses focus | Restores module/control identity after rebuilding the dashboard. Enter on Collapse, Expand and Move down retained the appropriate control. `dashboard-focus-fixed.json`. |
| Fabric device checkbox loses focus | Restores the stable device checkbox. PE-C was toggled off/on with Space; focus and checked state stayed aligned. `fabric-device-focus-fixed.json`. |
| Use in trace retains guidance from an earlier route scenario | Programmatic route seeding refreshes the guide. Starting from an MTU-drop scenario and seeding PE-C's route changed both selection and guidance to Any router to any router. `route-seed-guide-fixed.txt`. |
| Node route labels core candidate_next_hop as unknown | Uses the core Candidate next hop label. Browser route output showed it for P1 and P2. `route-candidate-label-fixed.txt`. |
| Superseded event-log reads are left active | Changed query keys abort obsolete page/locate reads while retaining stale-result checks. Focused transport tests cover cancellation. Client abort is not evidence that backend CPU work stopped. |

Parent review found a further instance of the navigation race: a pending jump
to A could still replace loaded B's lanes after B was selected, because B did
not need another query. The final repair checks navigation authority before
normalization. Ordinary window requests retain independent authority and requery
when the selected resource/root context changes. Tests compose the real request,
jump, selection and normalization functions instead of stubbing the refresh.
Browser replay after the final reload confirmed ordinary loaded-resource
selection and window refinement complete; exact response ordering is covered by
the controlled regressions, not claimed from manual timing.

The final build also repeated Selected mode's switch to unloaded `etg-001874`
and settled at one lane (`final-selected-resource-settled.txt`). The final
console read returned no warnings or errors (`browser-console-final.json`).
The browser was restored to the loaded overview with 13 representative resource
lanes, two source lanes and the full 0–720 second window (`final-overview.txt`).

## Skill-led implementation and checks

Three fresh `gpt-6.1-sol` agents used `router-plugin-author` with short
behavioral tasks and disjoint ownership. They did not receive conversation
history, audit diagnoses or probe outputs. The author/validator skills and
validation map were updated before dispatch; their hashes and exact prompts
are in `.runtime/audit-fixes-final-2026-10-20/dispatch.md`.

Parent review prompted follow-up fixes for selected-target query context,
consumed log keyboard intent, and stale timeline payload application. The first
full run also exposed two outdated startup harnesses; they now use the real
lane-mode helpers while preserving the startup assertions. The validation map
was then extended with the composed request/normalization lesson. Sol reviewed
the final guidance against the implementation and regressions and reported no
material gap. This was an iterative skill-led implementation, not a claim that
the first pass needed no feedback.

- `npm --prefix frontend run check`: frontend contract valid; **428 tests
  passed, 0 failed, 0 skipped, 0 cancelled**. Final output:
  `.runtime/audit-fixes-final-2026-10-20/frontend-check-final.log`.
- `quick_validate.py` for both repository skills: valid.
- `python scripts/check_plugin_conformance.py --list`: declaration inventory
  passed. This is not a full conformance-suite result.

Browser screenshot capture was unavailable in this session. Saved DOM snapshots,
focused DOM/focus observations and console checks provide the browser evidence;
no screenshot-based visual certification is claimed. The million-event fixture
was used for interaction checks, but CPU/RSS and cold projection timing were not
remeasured in this frontend task. The earlier cold safe-projection cost remains
a separate performance baseline, not a frontend regression fixed here.

## Plug-in documentation drift check

Completed for the task-owned changes. These repairs preserve existing generic
UI semantics, declared edge direction and descriptor boundaries. They add no
plug-in hooks or public contract changes. The author/validator skills and
validation map carry the new checks; the quickstart, normative contracts,
runnable example and author-facing README commands require no changes.
