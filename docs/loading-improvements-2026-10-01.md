# Initial loading improvements — 2026-10-01

Implementation checklist, in order:

- [x] 1. Render reconstructed topology before secondary route data; trace on request.
- [x] 2. Reuse bounded compilation results without caching trust or skipping live identity checks.
- [x] 3. Load independent node panels concurrently and avoid duplicate startup requests.
- [x] 4. Reduce first-access archive work while retaining archive validation.
- [x] 5. Report loading stages accurately and provide bounded waits and retry paths.
- [x] Update repository skills and validate their use with fresh GPT-6.1 Sol agents.

## Baseline

At commit `9c702895945773dac48c42e6ff1d6c604a8944ab`, one fresh-process
sample using the retained ten-node development fixture (300 baseline events
and 120 baseline resources per node) measured:

| Direct backend phase | Seconds |
|---|---:|
| Runtime import | 1.591 |
| Runtime open | <0.001 |
| Topology construction | 15.445 |
| First topology query | 5.941 |
| First route trace, reusing topology context | 5.913 |
| Repeated route trace | 6.127 |

A separate cProfile process attributed 17.092 of 18.278 construction seconds
to module-target fingerprints (50 calls), and 7.622 of 7.809 first-query
seconds to provider validation (20 calls). Compilation accounted for 5.249
construction seconds. Cumulative timings overlap and must not be added.

These are direct provider calls, excluding fixture generation, HTTP, browser
rendering and route-table loading. The filesystem cache was uncontrolled.
Raw local evidence is in `.runtime/loading-audit-2026-10-01`; these ignored
artifacts are not shipped in Git. See also the earlier
[profiling method and limitations](topology-route-profile.md).

## Implementation and validation

### 1. Progressive topology loading

Route capability discovery runs alongside reconstruction. The committed map
renders immediately; route tables retain their own abort controller and use
only the committed context. Reconstructing again cancels obsolete table work.
Route tracing requires explicit submission. Pending/unavailable capability
messages and control availability survive either request completion order.

Validation: seven new behavioral tests plus nine existing route-control tests
passed. An independent review exposed and prompted a fix for the empty trace
renderer overwriting capability-loading text. The parent also replayed the
first 15 tests. Node initially hit a sandbox path-resolution denial before
executing tests; the same tests passed with the permitted host execution.

### 2. Compilation artifact reuse

Core retains immutable compiled declarations keyed by module name, exact
source bytes, and optimization level. The process-local LRU permits 16 entries,
1 MiB of retained source, and 256 KiB per source; existing code-object limits
also apply. These are source-byte bounds, not a measured total heap limit.
Source reads, live runtime/dependency inspection, execution pins, and final
source/stat validation remain mandatory. No attestation result is cached.

Validation: 119 identity, provider, router, and process-boundary tests passed.
New tests cover warm-cache runtime/default/global changes, same-size source
edits with preserved timestamps, deletion, file replacement during validation,
oversized input, failed compilation, and eviction. Independent review found
no correctness issue. No plug-in hook or public signature changed.

A fresh uninstrumented sample of the same small fixture measured topology
construction at 6.214 s (baseline 15.445), first query at 2.418 s (5.941),
first trace at 2.455 s (5.913), and repeated trace at 2.539 s (6.127).
These single-sample comparisons are observations on a shared host, not a
latency guarantee or browser benchmark. Evidence: local
`.runtime/loading-improvements/after-compilation.json` and `identity-parent.log`.

### 3. Concurrent node startup

The timeline, incident preview and topology capabilities begin independently.
The first display waits for the timeline; optional panels finish independently.
Initial selection establishes the cursor and resource before the panel request
batch, avoiding duplicate graph/resource/temporal requests. A late preview
cannot replace explicit navigation or an existing user selection.

Validation: 26 startup, timeline-authority and topology-authority tests passed.
Independent review found a follow-cursor race when capabilities arrived first:
suppressing a duplicate timer also suppressed the topology time-input update.
That synchronization now happens immediately, with behavioral coverage.

### 4. Sequential archive access

Before the archive change, direct `DemoAssemblyStore` construction took
0.331 s for the 1,361,229-byte development archive and 25.890 s for the
retained 286,514,932-byte full-size archive (ten nodes each). These fresh-process
samples exclude provider identity, history materialization, HTTP and browser
work. The full-size archive is an existing runtime-compatible fixture, not a
new canonical generator build. Neither archive nor its existing lock was changed.
Evidence: local `.runtime/loading-improvements/archive-baseline`.

The loader now streams the outer archive twice through one open descriptor,
compares both passes' member headers and metadata, and copies/checksums packs
in physical order while retaining manifest order for revision descriptors.
The nested projection scanner still traverses trailing members.

Validation: 27 archive tests passed, including reordered packs with metadata
last, between-pass changes, missing members, bad sizes/checksums, and trailing
unsafe, duplicate or nonregular entries. Parent replay also passed; independent
review found no issue. Constructor samples after the change were 0.277 s for
small and 24.458 s for full (about 16% and 6% lower respectively). These isolated
single-sample gains are modest and do not establish browser startup latency.
Evidence: local `.runtime/loading-improvements/archive-after` and
`archive-parent.log`. No plug-in API or accepted format changed.

### 5. Progress and recovery

Core now reports archive reading, provider attestation, reconstruction, route
tables and traces at their execution boundaries. Nested work on the same
tracker shares one lifecycle, restores the parent stage on success and retains
the failing stage on error. Advisory record counts retain their high-water
mark. Provider checks and native process-control exceptions remain enforced;
expected core-translated 4xx responses do not mark successful loading failed.

The browser JSON transport bounds waiting, including response-body decoding,
to 180 seconds by default (an override may use 1–300,000 ms). Progress polls
use 10 seconds. Caller cancellation and error contracts remain intact, and
timeouts never replay work through topology endpoint aliases. Startup errors
clear loading placeholders and offer an explicit retry; the topology page
also links to the node workspace. A browser timeout does not stop or establish
completion of synchronous server work.

Independent frontend review caught timeout replay through fallback endpoints;
this was fixed and covered at the caller level. Backend review found no issue.
Final parent checks passed: 142 identity/progress/provider/router/process
boundary tests; 372 frontend tests; strict typing for 141 package modules and
two public consumer files; generated/verified stubs for 141 modules. The
frontend source/manifest contract also passed. Local logs are under
`.runtime/loading-improvements`. The final documentation/archive smoke replay
passed 45 tests, recorded in `docs-archive-final.log`.

## Live browser verification

The retained small assembly was served on port 8878 with the changed code.
The page rendered ten nodes and 693 route rows. Tracing remained idle until
**Trace route** was clicked; the resulting bidirectional route was reachable,
with two candidates per direction and the expected PE-A → P1 → PE-B path.
The PE-A node page displayed 305 events and 130 resources, preserved its
topology context and had no console errors. The HTTP log records one initial
timeline, graph, resource, dashboard and node-topology request each. Two
route-table requests were pagination for the 693 rows, not duplicate startup.

The parser-only sensor plug-in on port 8879 showed an explicit unavailable
topology state. Manual reload returned the same honest state, and **Open node
workspace** led to its two-resource workspace. This addresses the stuck-loading
portion of B1 in the [earlier browser audit](plugin-browser-audit-2026-09-30.md).
The earlier B2–B4 findings were outside these loading changes and remain open.
Screenshots and HTTP logs are retained locally under
`.runtime/loading-improvements`; they are not shipped in Git.
The verified demo remains available at `http://127.0.0.1:8878/`; the temporary
sensor validation server was stopped after inspection.

One visual follow-up was observed: the node correlation graph can initially
show overlapping cards and horizontal overflow at the browser's current
viewport. This was not diagnosed as a regression from these changes; graph
layout needs a separate investigation. The browser exercise used the small
fixture, not a full-size startup benchmark. Slow/failing request ordering and
deadline behavior were verified by behavioral tests, not by waiting three
minutes for an intentionally stalled live server.

## Skill use trials

Fresh `gpt-6.1-sol` agents received no conversation history, API hints, test
names or implementation steps. Both trials were given only a task, skill path
and isolated output directory. Exact prompts, hashes and artifacts are retained
in `.runtime/loading-skill-trials`.

- Author task: implement and test a tiny precomputed-fixture adapter that
  loads on first use and reports progress. The first six tests passed, but
  artifact review found inaccurate archive/indexing labels. The author skill
  was refined to tie each stage to actual work. A fresh agent repeated the
  identical prompt; its four tests and parent replay passed with accurate
  `loading_revision` reporting. This trial validates the progress API utility,
  not a registered plug-in or complete runtime session. Its configurable byte
  limit still needs argument validation before this temporary utility could be
  reused as production code; the trial tests use positive limits.
- Combined validation task: validate the updated identity cache in a
  topology-and-route workflow. The agent ran the API inventory, 16 targeted
  boundary tests and a new generated-assembly scenario with exact member
  revisions, retained context, stable cold/warm route payloads, and rejection
  followed by recovery for an unknown context. Parent replay of that scenario
  passed. Source changes, runtime mutation and eviction were checked in the
  focused boundary tests, not injected into the generated assembly itself.

Final author skill SHA-256:
`074797D1D162756F47819C38C42000055A251B9169B8B36FB63F49271E5B50A0`.
Validator skill SHA-256:
`AE7F21C4AD4942E2527A0FDF3B368D152725FBB1D76EFCE84CBF3D9A9C0F207D`.
Both skill format checks passed. Initial trial import/dependency limitations
were recorded without disabling identity checks; the parent used the installed
Python 3.12 demo environment for integration validation.

The plug-in documentation drift check updated the quickstart, normative
contract, author guide, runnable demo documentation, API/architecture references
and relevant README links/descriptions. No new plug-in hook was introduced.
This change's validation is targeted; it is not a repeat of the prior entire
repository conformance audit.
