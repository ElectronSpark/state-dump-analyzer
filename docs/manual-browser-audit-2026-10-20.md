# Manual browser audit — 2026-10-20

Follow-up changes and validation are recorded in
[the audit remediation report](audit-fixes-2026-10-20.md). The observations below
describe the original audited version and remain unchanged as evidence.

## Scope and environment

This audit uses the actual browser UI through clicks, typing, selection, keyboard
navigation, file choosers, and clipboard checks. Source inspection, server logs,
and process samples supplement the observations; they do not substitute for a
successful UI workflow. Production code was not changed.

The checkout is `aaf9758` plus the uncommitted navigation-memory optimization.
The server uses the configured Python 3.12 demo environment, current source
frontend, and `router-state-lab-algorithms-2026-10-02.tgz` (approximately 1.25M
events per node). It listens on loopback port 8883. The previous server was no
longer running. Windows sandbox launch attempts failed to retain a working
listener; the approved launch outside the sandbox succeeded.

Durable test state is isolated under
`.runtime/manual-browser-2026-10-20/control-plane`, with tenant/project
`manual-audit`, workspace `workflow`, and principal `local-reviewer`. The user
explicitly approved creating synthetic test data after automatic approval review
blocked workspace creation. Imported inputs are the existing small before/after
workbench fixtures. No external model service is used.

After the main audit, the user explicitly approved enabling client-safe access
for the repository's offline scripted private-analysis runner in this workspace.
That follow-up was completed through the browser and the policy was returned to
disabled afterward.

Evidence, screenshots, server logs, and one-second process samples are under
`.runtime/manual-browser-2026-10-20/`. Browser timings below include transport and
rendering; observations bracket completion where another UI was being exercised.
This is an interactive mixed-workload audit, not a controlled benchmark.

## Findings recorded during the audit

### P2 — Cold full-text search has a long visible wait

On a fresh search-cache directory, enter `failure` in the node event search.
The interface displays “Building query indexes” and “Waiting for the next
bounded progress update.” It was still loading at 60.6 seconds and was complete
by the 100-second observation, returning 24,925 matches. Other UI operations and
a small import were exercised concurrently.

The same search after a zero-result refinement returned in approximately
325 ms, including the browser interaction and debounce. The published sidecar
is 75,038,720 bytes. This indicates a cold-path cost rather than uniformly slow
search. A useful improvement is bounded progress reporting and investigation of
the full-corpus safe-text projection/index construction path.

### P2 — Tiny durable ingestion is slow

Uploading the 752-byte before fixture with automatic parser selection succeeded,
but its durable event timestamps span 53.999 seconds. Of that, 49.083 seconds
falls between `ingestion_started` and `revision_staged`; probing took 3.214
seconds and publication about 0.644 seconds. It produces three resources, three
source records, no events, one relationship projection, and one finding.

This import overlapped cold million-event search. The duration is measured;
attribution to CPU contention, identity checks, or filesystem work needs a
separate profile. It is not an ingestion failure or a deadlock.

### Potential P2 — Ctrl-click selection does not match the event-log instructions

Reproduction in the in-app browser on Windows:

1. Search normalized events for `failure`.
2. Clear selection, then click the row at `+600.075 s` for `dte:svc-000009`.
3. Ctrl-click the row at `+600.077 s` for `dte:svc-000029`.
4. The toolbar still reports one selected row; the first row remains selected.

The behavior repeated using the second row. Shift-clicking the third row selects
three and copying returns all three expected event texts. Source inspection has
not yet established a double-toggle or platform-specific cause; the possibility
of an input-tool/browser interaction remains open. This is a reproduced
interaction problem under the audit tool; it still needs reproduction with a
physical mouse before assigning it conclusively to application code.

### P3 — Node-page header overflows the viewport

At the existing desktop browser size, the node page has a horizontal document
scrollbar and the “Review gaps” control extends past the right edge at the
normal left scroll position. A DOM
observation measured document width 1,282 CSS pixels against a 1,265-pixel
viewport. Horizontal auto-scrolling can also shift the left edge of the header.
After auto-scrolling horizontally by 16.8 pixels, the header's left coordinate
was -16.8 pixels and the review button's right coordinate was 1,265.01 pixels.
The screenshot `node-header-overflow.jpg` records the global scrollbar and lost
header margin.

Source inspection identifies the nonwrapping navigation and header minimum
columns as likely contributors. No responsive viewport override was used.

### P3 — Connection-reset traceback pollutes the server log

The audit generated a Windows asyncio
`_ProactorBasePipeTransport._call_connection_lost` traceback with
`ConnectionResetError: [WinError 10054]`. Requests continued successfully and no
matching visible user failure has been established. Record it as diagnostic
noise until a specific failed workflow is correlated. Two identical callbacks
were present at the end of monitoring, with no application-code exception stack.

### P3 — Removing a session member leaves an earlier error on screen

First try to save a duplicate revision under another member ID. The page correctly
reports `a session may contain each immutable revision only once`. Next remove
an existing member. The member disappears and the session version increments
from 3 to 4, but the top status still reports the old duplicate-revision error.
Re-adding the member succeeds, increments to version 5, and clears the error.

The remove-member handler in `frontend/assets/management_workflows.js:118`
performs the request and rerenders without updating the status. Save-member
explicitly sets a success message at line 131. This is stale feedback; the
membership mutation itself succeeded.

### P3 — Rejected upload continues to say “Uploading…”

Choose a file and enter `invalid node` as its node identity hint. Upload rejects
the whitespace-containing hint and displays the correct validation error in the
page-wide status. However, the upload form continues to show
`Uploading unsupported-audit.txt (115 bytes)…`, with its submit button enabled.
The error can be above the viewport while the stale progress text remains next
to the form. This repeated on a second attempt.

`stale-upload-feedback.jpg` shows the visible form; the full-page companion
`stale-upload-feedback-full.jpg` includes both the error and stale progress.
Clearing the stale progress text and keeping the validation message adjacent to
the form would make the failure clear.

## Exercised workflows

| Surface | Browser actions and observed result |
| --- | --- |
| Node startup | Visible inventory and parsing progress; PE-A loads 1,250,005 events and 7,510 resources. Management remained responsive during parsing. |
| Timeline range | Reversed endpoints rejected with “End must be at or after start.” A 120–120.01 second range zoomed correctly. |
| Timeline navigation | Zoom, pan, fit, back/forward view, reset, and Alt+Left tested. Range clipboard output preserved the selected endpoints. |
| Timeline lanes | Combined/separate views, picker, empty resource search, invalid regex rejection, and a custom `timeout\|failure` source lane tested. |
| Event search | Cold `failure`, warm repeat, zero-result refinement, clear, layer filter, normalized/source inclusion combinations tested. |
| Large log navigation | Ctrl+End reached the final normalized rows through the approximately eight-million-pixel virtual scroll extent; retained-source end navigation also worked. |
| Event selection | Single/Shift selection and copied evidence worked. Ctrl-click issue recorded above. |
| Browser markers | Marking three events, hiding/showing marks, and revealing in timeline worked. Selection remained three after asynchronous refresh. |
| Durable review mismatch | Connecting the large node to the unrelated small imported revision was rejected; markers stayed browser-local. Correlation writing was correctly disabled without a matching writable durable revision. |
| Resource tables | Empty search, clearing, and changing resource type were exercised; empty results were explicit. |
| Correlation graph | Focused/full scope, collapse/expand, selected-time refresh, and bounded full-graph explanation worked. |
| Consistency | Four pass findings rendered separately from fail/unknown counts. |
| Node topology | Invalid nanoseconds rejected; absolute and relative basis, best-effort clock mode, projection change, and reconstruction exercised. Partial node coverage remained explicit. |
| Local route projection | Default ECMP and recursive route selection resolved as local declared projections, distinct from cross-node trace outcomes. |
| Dashboards | Open module, collapse, move down, reset layout, and authoritative selected-time sample updates exercised. |
| Review notes | Temporary note copied correctly, then cleared; Copy review brief returned the workspace and selected gaps/notes. |
| Projects/workspaces | Create and select isolated project/workspace worked after authorization. |
| Automatic import | Before fixture published successfully; timing issue recorded above. |
| Manual import | After fixture stopped at parser selection, cancellation worked, and a new upload with explicit parser selection published. |
| Invalid import and retry | Whitespace in node hint rejected. Unsupported 115-byte fixture reached `failed`, with no published revision and no validated parser candidate. Resume re-probed unchanged bytes and failed again at attempt 2/3, with explicit durable event history. |
| Revision inspector | Summary, resources, empty events, relationships, before error finding and after informational finding inspected. Revision-level correspondence remained distinct from timed observations. |
| Sessions | Create, add two same-node revisions, set default, rename, reject a duplicate immutable revision, remove/re-add a member, change default, switch inspected member, filter to zero resources, and reset filters. Stale error after removal recorded above. |
| Snapshots | Freeze at session version 2, rename live session to version 3, inspect unchanged two-member frozen analysis. |
| Administration | Configuration read, disabled retention preview, and bounded audit read. No destructive retention executed. |
| Health | Runtime/search ready, queue workers healthy, no pending/stalled imports. Separate instance-operator restriction displayed correctly. Opt-in refresh exercised. |
| Private analysis | Disabled-policy behavior, approved client-safe offline execution, two validated citation references, durable report reload, cancellation, invalid selection/time/ID handling, and clearing/reconnecting browser scope. Policy restored to disabled; details below. |
| Fabric | Ten-node reconstruction, device filter including zero results, highlights, expanded device index, underlay/VPN display, element toggles, zoom/fit, attachment tooltip evidence, and Links/Contract content. Empty device selection rejected; Select all recovered the full vector. |
| Fabric time | Relative watermark and absolute UTC reconstruction under strict/best-effort policy. Keyboard Home/End on the status slider reconstructed the beginning/latest moment; pending selection was distinguished from the graph's current moment. |
| Route traces | Primary/standby, return direction, all/focused paths, recursive cycle, split-horizon block, MTU drop, exact MTU equality, incomparable MTU contracts, and hop limit 1. MPLS handoff mismatch correctly reported forward evidence inconsistency while preserving declared delivery; return path had no finding. |
| Route tables | Empty text search, clearing filters, node/VRF filtering, and management route inventory. Use in trace on the VXLAN mismatch return route populated the scenario, PE-B start, blue VRF, family/type, and return-only direction; execution returned the expected reachable return path. |
| Node/fabric navigation | PE-B loaded 1,250,002 events and 7,509 resources with the correct member revision and capture context. Back to multi-node topology preserved VPN display, element filters, ten members, relative time basis, clock policy, and route configuration. |

## Performance observations

The monitor collected 1,063 samples from 18:28:06 through 18:46:05 UTC. It was
then stopped; the demo server remains running. These are server-process figures,
excluding browser memory and separate worker-process CPU/memory.

| Approximate browser phase | RSS start → end | Maximum sampled RSS | Process CPU increase |
| --- | ---: | ---: | ---: |
| Initial node/search, 18:29–18:31 | 2.996 → 3.030 GiB | 3.061 GiB | 103.06 s |
| First fabric open, 18:34 | 3.035 → 3.667 GiB | 3.667 GiB | 12.58 s |
| Traces/subsequent actions, 18:35–18:46 | 3.222 → 3.015 GiB | 3.226 GiB | 136.70 s |
| PE-B navigation interval, 18:41–18:45 | 3.099 → 3.015 GiB | 3.099 GiB | 64.45 s |

The process-reported lifetime peak was **3,991,830,528 bytes (3.718 GiB)**, above
the one-second sampled peak of 3.667 GiB. Final monitored RSS was
**3,237,511,168 bytes (3.015 GiB)**. The full monitored interval added 289.83
process CPU seconds. Rows overlap; their CPU totals must not be added together.
Initial startup work preceded monitoring, and final UI edge-case checks followed
it.

Memory rose during the first fabric reconstruction and later fell. During the
PE-B interval it dipped to 1.865 GiB before returning to 3.015 GiB. These samples
do not establish a leak or attribute allocations to individual requests.
Phase timings include idle time and concurrent actions, so they are not route
or navigation latency benchmarks. No precise PE-B load latency was captured.

Source inspection supports a useful next performance investigation: browser
startup defers the search corpus build, while an API-only warmup may build it
before a benchmark starts. The first query serially projects safe event text,
serializes it, and constructs the compressed SQLite corpus. Cold-query progress,
this projection/build path, and fixed ingestion overhead warrant separate
profiles. CPU contention or Windows/OneDrive filesystem overhead remain
hypotheses, not established causes of the slow tiny import.

Final captured warning/error console logs were empty for the node, management,
and fabric tabs. The two server transport-cleanup exceptions are recorded above.

## Offline private-analysis follow-up

With the user's explicit approval, the browser changed only the synthetic
workspace policy to `client_safe`, with `in_process` allowed and local subprocess
transport disallowed. The only approved runner shown was
`demo.scripted-evidence-walk · 1.0.0 · in_process`. Its callback is a fixed local
evidence walk; it does not invoke an external model or interpret the question as
a diagnosis.

The successful run selected both before/after revisions, General evidence review,
and Latest per revision, with the question:
“Demonstrate the authorized interface evidence chain.”

| Check | Observed result |
| --- | --- |
| Successful execution | Run `ebd94e676d82432b913472d3d54205d2` completed at version 6. Created-to-updated durable timestamps span 1.5412634 seconds; the browser was observed complete by 10.7 seconds, not timed continuously. |
| Evidence report | Explicit “Scripted demonstration, not a model” summary, marked evidence-supported. Two exact safe citation references: one retained source record and one pinned provider capability result. |
| Citation identity | Both references identify the selected after revision and client-safe disclosure. Source reference includes exact absolute nanoseconds; provider result explicitly has unknown/open time. Visible references contain safe metadata rather than raw source payloads or filesystem locators. |
| Reload | Load run preserved the run ID, version, timestamps, request digest, outcome digest, and report. Clearing browser scope and reconnecting then reloading preserved the same durable result. |
| Empty selection | Submission rejected with `select 1 to 128 revisions`; no extra run was displayed. |
| Invalid time | Absolute `-1` rejected as negative; relative `0.5` rejected because nanoseconds must be a canonical decimal string. |
| Unknown run | Opaque all-zero run ID returned `resource not found`; subsequent valid lookup recovered normally. |
| Cancellation | Second run `e3d7f216b078470985adc9886e51a64c` reached `cancelled` at version 4 with a validated terminal cancellation result. No claims or citations were returned. |
| Clear from memory | Scope fields and Run ID cleared, and current run/report disappeared from the page. Reconnection required explicit scope entry. |
| Policy restoration | Policy version 2 is disabled, both runner transports disabled. Discovery disables runner/execution controls. The existing durable report remains readable. |

No additional defect was observed in these checks, and captured browser
warning/error logs were empty. The runner intentionally returns no proposals, so
proposal rejection/promotion was not validated. These small offline runs occurred
after the process-memory monitor stopped; the million-event metrics above do not
include them.

Evidence screenshots: `private-analysis-success.jpg` and
`private-analysis-cancelled.jpg` in the audit runtime directory.

## Coverage limits and retained state

This audit exercised all main UI surfaces and representative positive, empty,
invalid, and failure paths. It is not an exhaustive pass over every combination:

- Private-analysis proposal rejection/promotion was not exercised because the
  approved offline runner returns no proposals. No real model, subprocess runner,
  or full-fidelity disclosure was tested.
- Durable node review was tested for revision mismatch and browser-local fallback,
  not for a successful matching-revision write. The startup million-event revision
  is intentionally separate from the small durable imports.
- Permanent deletion, retention execution, and instance-operator operations were
  not performed. Their read-only/disabled states were inspected.
- The audit did not run all 32 route scenarios, every field combination, physical
  mouse drag gesture, multi-page catalog, browser, or viewport. Ctrl-click needs a
  physical-input reproduction. No mobile/responsive matrix was run.
- A completed browser workflow establishes its observed behavior on this fixture,
  not conformance of every plug-in API. This turn did not change production code
  or rerun the automated conformance suite.

The isolated workspace retains the before/after revisions, the session at
version 5 with `after` as default, its immutable version-2 snapshot, and the
deliberately failed unsupported import. It also retains one completed and one
cancelled offline private-analysis run. Disclosure policy is disabled again.
No existing user catalog was modified.
The demo is left available at `http://127.0.0.1:8883/`.

## Documentation drift check

This change records audit evidence only. It changes no public plug-in behavior,
protocol, parser, example, or authoring command. No authoring-set update or
production test rerun is required for this report.
