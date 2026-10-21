# Frontend recovery fixes — 2026-10-20

All four findings in the [frontend exploration report](frontend-exploration-2026-10-20.md)
are repaired. Three fresh GPT 6.1 Sol agents used the updated author skill to
implement separate areas. The parent reviewed the code and regression coverage,
then independently repeated the original workflows in the in-app browser.

## Changes and browser results

| Finding | Repair | Parent browser validation |
| --- | --- | --- |
| Timeline zoom/pan re-enables hidden layers | Refresh preserves known-layer choices, enables newly discovered layers, and ignores superseded responses. | On PE-A with 1,250,005 events and 7,510 resources, hiding Control plane reduced lanes from 13 to 9. It stayed hidden after the settled zoom response at 120–600 s and pan response at 72–552 s. Cached-window labels had cleared before the final observations. |
| Reconnect leaves a hidden required time field | Initial setup, clock changes, reconnect and clear synchronize visibility and native required validation. | Absolute clock initially made the visible time field required. Rediscovery reset Latest per revision with hidden/non-required/non-missing time. The actual create button produced a completed offline run without the previous clock-toggle workaround. Relative clock remained required; Clear from memory removed the constraint again. |
| Failed run lookup keeps creation disabled | A rejected initial lookup restores ready state, guarded by the current request generation. Discovery rendering preserves selected revisions and form values; old report/review authority stays cleared. | A missing opaque run ID displayed `resource not found`, removed the previous report, retained revision/task/query choices, and left Create enabled with no active-operation title. A subsequent create completed successfully. |
| Successful rename leaves an earlier error | The rename handler emits success feedback after PATCH and refreshed session display. | A duplicate-revision member attempt produced the expected error. Renaming then displayed `Session renamed.` and the new label at version 10. Restoring the original label advanced to version 11 with both members/default intact. |

Browser assets were reloaded from the checkout; the existing current-source
server remained on loopback port 8883, PID 32984. Node tests used
`router-state-lab-algorithms-2026-10-02.tgz`. Management and analysis used the
previously authorized synthetic control plane at
`.runtime/manual-browser-2026-10-20/control-plane`, tenant/project `manual-audit`,
workspace `workflow`, principal `local-reviewer`.

Both new analysis runs used the approved offline in-process scripted runner:

- Reconnect submission: `1147333c7d244f9bb54ba6d085f754b6`, completed version 6.
- Submission after failed lookup: `c35379dc10cf4ca78401760b08765310`, completed version 6.

Each displayed a validated report with two exact safe citation references. No
external model service was invoked. The synthetic runs remain as audit evidence.
The workspace policy was temporarily client-safe at version 5 and restored to
disabled at version 6 with both runner transports disabled. Analysis scope was
cleared from memory. The node tab was restored to Overview, all layers enabled,
and the full 0–720 s window.

## Regression coverage and checks

The changed production files are `frontend/assets/app.js`,
`management_workflows.js`, `private_analysis.js`, and
`private_analysis_controller.js`. Regression tests exercise:

- Production layer-toggle listeners, zoom/pan handlers, delayed requests,
  returning/new layers, and superseded query responses.
- Installed private-analysis form handlers with modeled native reset/required
  behavior, plus the actual adapter/controller/transport imports. The real
  browser independently confirms native form submission.
- Failed lookup recovery, cleared review authority, no mutation replay, late
  failure after scope/run replacement, and retained locks for an accepted active
  run whose later polling read fails.
- Installed management submit handlers through a rejected rename and a corrected
  successful retry, checking refreshed data and cleared error styling.

Parent final check, Node v20.17.0:

```text
npm --prefix frontend run check
Frontend contract valid: 5 routes, 16 JavaScript modules, one source distribution.
404 tests passed; 0 failed, skipped or cancelled.
```

This final complete run had local loopback permission and included all new test
files. Earlier agent runs encountered sandbox `EACCES` in the proxy tests; an
intermediate run also saw private-analysis tests while they were being edited.
Those are superseded by the final same-code result. The full final output is
saved in `.runtime/frontend-fixes-2026-10-20/frontend-check.log`.

Both skills passed `skill-creator/scripts/quick_validate.py`. The conformance
declaration inventory (`python scripts/check_plugin_conformance.py --list`) and
`git diff --check` passed. This inventory check is not a full API conformance run.
Browser warning/error logs were empty for all three tabs; the server error log
contained startup messages only.

## Skill use

The author and validation skills now route frontend repairs to the API map's
[state and recovery checks](plugin-api-validation.md#frontend-state-and-recovery).
The guidance distinguishes discovered data from user choices, form values from
dynamic validity, and failed reads from active accepted runs. It calls for
settled asynchronous results and actual failure-to-success UI transitions.

Three agents used `gpt-6.1-sol`, high reasoning, with no inherited conversation.
Their opening tasks were:

```text
Use .agents/skills/router-plugin-author/SKILL.md to fix timeline layer visibility being lost after zoom or pan. Add regression coverage.

Use .agents/skills/router-plugin-author/SKILL.md to fix two private-analysis UI bugs: reconnecting after choosing an absolute clock leaves a hidden required time field blocking submission; a failed run lookup leaves creation disabled as if an operation were active. Add regression coverage.

Use .agents/skills/router-plugin-author/SKILL.md to fix successful session renames leaving an earlier error displayed in management. Add regression coverage.
```

Each prompt additionally assigned disjoint frontend files/tests, required
preserving other work, excluded prior audit/trial reports, other agents' outputs
and parent logs, and prohibited browser use, docs/skill edits and commits.
The management agent was allowed to reuse the existing management entry test
harness. No implementation steps or expected assertions were supplied.
The parent authored the skill update before dispatch and kept it fixed.

SHA-256 at dispatch and completion:

| Material | Hash |
| --- | --- |
| Author skill | `c080e706904946a424a7832cc23ec60b3e513b609c0a8196b1e0a908e12259a2` |
| Validation skill | `99ea2583a04870bfa7e68053814fa1a8a2760d9e04f871bddb9fc792b0e9cdc4` |
| API validation map | `57da688d55a340424419a401e1ffc60b6e64035b6f7897f695f6ff93b1ffa36e` |

These trials demonstrate skill-guided implementation of the requested frontend
repairs, not exhaustive plug-in API coverage.

## Evidence and scope

Screenshots, DOM snapshots, browser logs, source hashes and the full test log
are under `.runtime/frontend-fixes-2026-10-20/`. Key files are
`timeline-after-zoom.txt`, `timeline-after-pan.txt`,
`private-time-validity.json`, `private-reconnect-success.txt`,
`private-failed-lookup-recovered.txt`,
`private-after-lookup-new-run-success.txt`, `session-rename-success.txt`,
`session-restored.txt`, and `policy-restored.txt`. Screenshots accompany the
zoom, completed reconnect, failed-lookup recovery and successful rename states.

The browser pass covers the four reported workflows and nearby recovery cases;
it is not an exhaustive browser/viewport matrix or a new CPU/RSS benchmark.
Existing pending backend optimization work was preserved. No commit or push was
performed. Documentation drift check completed: these are generic frontend
repairs with no public plug-in behavior or author-facing command change, so the
maintained quickstart, contract, runnable example and README need no update.
