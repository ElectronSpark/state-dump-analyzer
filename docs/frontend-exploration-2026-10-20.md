# Frontend exploration follow-up — 2026-10-20

Follow-up: all four findings below were repaired and independently checked in
the browser; see the [fix validation report](frontend-fixes-2026-10-20.md).
The original observations below are retained as the pre-fix evidence.

Four additional bugs were reproduced through the browser. No production code
was changed in this audit. This follows the earlier
[manual audit](manual-browser-audit-2026-10-20.md) and its
[remediation report](audit-fixes-2026-10-20.md).

## Environment and method

The checkout is `f4076ce` plus the uncommitted validation-record and projection
changes described in [their report](validation-projection-2026-10-20.md). The
existing server predated those changes, so the parent restarted that identified
local demo on port 8883 with current source and the configured Python 3.12.13
environment. The browser was explicitly reloaded. The fixture remains
`router-state-lab-algorithms-2026-10-02.tgz`; PE-A has 1,250,005 events and 7,510
resources. The refreshed server PID is 32984.

The parent exercised the actual in-app browser using clicks, form entry,
selection and keyboard commands. Read-only DOM inspection supplied native form
validity and disabled-button evidence. A GPT 6.1 Sol agent used the repository
validation skill to suggest source-supported candidates and run frontend
checks; the parent independently reproduced all four candidates in the UI and
reviewed their source paths.

Synthetic durable state remains in the previously authorized
`.runtime/manual-browser-2026-10-20/control-plane`, tenant/project `manual-audit`,
workspace `workflow`, principal `local-reviewer`. The user's existing approval
for the offline synthetic runner was used for private-analysis recovery tests.
No external model or network model service was invoked. Screenshots, DOM
snapshots, browser logs and server logs are under
`.runtime/frontend-exploration-2026-10-20/`.

## P2 — Timeline navigation re-enables a hidden layer

Reproduction on the large node:

1. Open Timeline with all three layer chips enabled. The lane control reads
   `13 / 7,510 · 2 logs`.
2. Disable **Control plane**. The chip becomes unpressed and the lane count
   falls to `9 / 7,510 · 2 logs`.
3. Click **Zoom timeline in**. The visible window changes from approximately
   0–720 seconds to 120–600 seconds.
4. When the timeline response finishes, **Control plane** becomes pressed again
   and the lane count returns to 13, without a user request to show that layer.

The parent repeated this by hiding Control plane and clicking **Pan timeline
earlier**; the layer was enabled again after the response. This is conditional
on layers returned by the timeline request: the Hardware driver chip stayed off
in a separate check where its lanes were not returned.

Source: `frontend/assets/app.js:7686–7694`. `refreshScaleTimeline()` adds every
returned lane's layer to `state.activeLayers` before rerendering. Normal refresh
therefore overwrites an explicit visibility choice. Layer discovery/default
initialization should be separate from preserving the user's active selection.

Evidence: `layer-before-zoom.txt`, `layer-after-zoom.txt`,
`layer-after-zoom.png`, `layer-after-pan.txt`.

## P2 — Reconnecting leaves a hidden required time field that blocks creation

Reproduction in the synthetic workspace with the approved in-process runner:

1. Discover the workspace and choose **Absolute Unix nanoseconds** under Clock.
   **Selected time (nanoseconds)** becomes visible and required.
2. Click **Discover workspace** again. Clock resets to **Latest per revision**
   and the time field disappears.
3. Select a valid revision, **General evidence review**, the approved scripted
   runner, and enter a question.
4. Click **Create and execute once**. No run appears and the button remains
   enabled; no useful validation message is displayed beside the form.

Read-only DOM inspection showed `pa-time` still had `required=true`,
`disabled=false`, `validity.valueMissing=true`, and no rendered client rectangle.
The native form cannot submit while this invisible text input is invalid.

Changing Clock to Absolute and then back to Latest fixed the form. Clicking the
same create control with the same revision/question then produced completed
offline run `685a49f58f0f47a994db9824fd1bb296`, terminal version 6, with two exact
safe citation references. Its durable created/updated timestamps span about
1.30 seconds; this is not a browser-latency measurement.

Source: `frontend/assets/private_analysis.js:432–439` resets the form and hides
the field without resetting its dynamically assigned `required` attribute.
Only the Clock change handler at lines 466–468 updates that attribute. Form
reset/reconnect needs to synchronize both visibility and native validity rules.

Evidence: `private-hidden-required.json`, `private-hidden-required.txt`,
`private-hidden-required.png`, `private-workaround-success.txt`.

## P2 — A failed run lookup leaves new-run creation disabled

1. In the eligible connected workspace, confirm **Create and execute once** is
   enabled after the completed run.
2. Enter nonexistent run ID `00000000000000000000000000000000` and click
   **Load run**.
3. The request completes with **resource not found**, but **Create and execute
   once** stays disabled. Its title reads **A private-analysis operation is
   already active.** No run is active in this page.

The old report is correctly cleared, but the operation state is not recovered.
Loading the valid completed run restored the report and re-enabled creation.

Source: `frontend/assets/private_analysis_controller.js:1022–1038`. `reload()`
publishes phase `loading` before `getRun()`; a rejected lookup has no phase
restoration. Creation eligibility requires a ready/terminal phase around line
546. The UI catch at `frontend/assets/private_analysis.js:489–496` only changes
the visible error message. Error cleanup needs to restore a usable state while
preserving generation checks and keeping the rejected report cleared.

Evidence: `private-failed-lookup.txt`, `private-failed-lookup.png`. The parent
also read the disabled property and exact button title through the browser.

## P3 — Successful session rename preserves an earlier error

1. Manage the synthetic `manual-session`, initially named **Renamed manual
   audit**, version 7, with its before/after members.
2. Try adding the existing after revision under a new member ID. The server
   correctly rejects it with **a session may contain each immutable revision
   only once**.
3. Rename the session to **Frontend recovery check** and save.
4. The name changes and version advances to 8, but the top status still shows
   the duplicate-revision error. It also remains visible after leaving the
   Sessions section.

This is a separate handler from the earlier fixed remove-member case. Source:
`frontend/assets/management_workflows.js:125` performs PATCH and `show()` without
setting success feedback. The parent restored the original name, leaving
version 9 with both original members and the same default member.

Evidence: `session-rename-stale-error.txt`, `session-rename-stale-error.png`,
`session-restored.txt`.

## Other exercised paths

| Path | Observation |
| --- | --- |
| Startup and concurrent management | Large-node parsing progress advanced and completed; management discovery and session controls remained usable during loading. |
| Resource filtering | A nonexistent resource search produced an explicit empty state. Switching resource type and clearing the filter recovered the IP-route table. |
| Nanosecond range | 120.000000001–120.000000002 seconds retained the exact endpoints and a 1 ns duration, with zero events and no endpoint differences. |
| Timeline navigation | Back/forward view, Fit, and Escape clearing the range worked; all layer chips and the default resource tab were restored afterward. |
| Private-analysis recovery | Clock toggle recovered submission; the offline run completed; valid lookup recovered creation after the failed lookup. Clearing from memory removed scope/run/query controls. |
| Fabric startup | Ten-node reconstruction and 693 route rows were visible by the 34.705-second observation. This is an observation upper bound, not exact request latency. |
| Counterfactual route | Forced alternate forwarding through P2 remained labeled Counterfactual/Available alternative, with explicit forced packet evolution. |
| Scenario replacement and return-only trace | Switching to IPv6-over-IPv4 reset steering to the observed decision. Return-only trace was reachable, selected Return, disabled the not-run Forward tab, and showed encapsulation, outer forwarding and decapsulation. |
| Logs | Captured warning/error console lists were empty in all four tabs. The refreshed server error log contained startup messages only at audit completion. |

No additional performance regression was established in these checks. The
background process monitor failed to produce a sample file, so there are no
per-action CPU/RSS measurements for this pass. A final permitted process read
reported RSS 3,252,678,656 bytes (about 3.03 GiB), lifetime peak RSS 3,268,599,808
bytes (about 3.04 GiB), and 116.984375 total CPU seconds since startup. These
include mixed node/fabric/route work and exclude browser and separate worker
processes; they are not comparable to the controlled backend-only benchmark.
The monitoring failure is an audit-harness limitation, not a product finding.

## Automated checks and retained state

The standard frontend check used Node v20.17.0. Its contract check passed for
five routes and 16 modules. The first restricted-sandbox run reported 392 tests:
381 passed and 11 failed, all from the proxy integration test's loopback
`EACCES`. Retrying the affected `dev_proxy.test.mjs` with the necessary process
permissions passed all 13 tests in that file. All original tests are covered by
passing results across these runs; this was not a single clean 392-test run.
These existing tests did not detect the four browser interaction bugs above.

Logs: `source-review/frontend-check.log` and
`source-review/frontend-dev-proxy-retry.log`. The plug-in conformance declaration
inventory also passed; no broader API-conformance claim is made.

The workspace policy is restored to **disabled**, version 4, with both runner
transports disabled. The session's original label/membership/default are
restored; its version is 9. The one successful offline run remains as synthetic
audit evidence. No retention/deletion, proposal promotion, or external-model
execution was performed. The current demo remains running on loopback 8883.
The user's node tab was returned to its overview with all layers enabled, no
selected range, cleared resource search, and the original ETG resource tab.

Scope limits: this is a targeted follow-up, not an exhaustive browser, viewport,
accessibility, route-scenario, import, or concurrency matrix. The four findings
are recorded for repair; no product fix is claimed. Existing uncommitted work
was preserved. Documentation drift check completed: this audit adds evidence
only, so no maintained plug-in authoring material requires an update.
