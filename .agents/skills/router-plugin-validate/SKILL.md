---
name: router-plugin-validate
description: Audit Router State Lab plug-in API conformance, documentation drift, or interactions between parsers, revision hooks, providers, and runtime adapters. Use for requested validation or audits, including individual and combined API checks.
---

# Router plug-in validation

Use the repository root containing `src/router_dump_analyzer`. When this skill
is supplied by absolute path, the repository is three directories above the
skill folder. Read `AGENTS.md` and [the API validation map](../../../docs/plugin-api-validation.md).

## Establish scope and evidence

Identify the requested hook, protocol, or combined workflow from the map. Compare
the implementation and typed signature with the relevant contract section and
tests. Distinguish a parser capability, a schema descriptor, a core service,
and a compatibility-runtime extension before proposing another plug-in hook.

Run `python scripts/check_plugin_conformance.py --list` to check inventory drift.
This checks that declarations have a conformance group; it does not prove every
method or behavioral branch is tested. For an individual hook, select relevant
module/class/method tests from the mapped suites. Use `--group` for a complete
surface or shared behavior change. For a full plug-in audit run `--all`;
a whole-repository audit also needs the demo,
generator, frontend, and typing checks listed in the map.

Reuse completed checks for the same code: full core discovery already includes
the grouped test modules, so run the inventory check and any new scenario
instead of repeating overlapping groups. Keep verbose logs for broad runs;
small generated assemblies can still require several minutes of setup.

Use one installed Python environment throughout. Verify its executable and
required imports first; if dependencies are missing, inspect the configured
environment via the map's troubleshooting steps before using source-only paths
or reporting the dependency unavailable. Prefer the documented
`unittest` runner: pytest's default assertion rewriting changes fixture plug-in
bytecode and can fail executable-identity checks. If a focused pytest command
is needed, use `--assert=plain -p no:cacheprovider`. A missing dependency, denied
cache path, or platform skip is a validation limit, not a product regression.
Capture the exact failure and rerun only the affected check after resolving it.
For executable-identity failures on unchanged imported code, follow the map's
[environment troubleshooting](../../../docs/plugin-api-validation.md#executable-identity-troubleshooting).
Do not treat a registration-only fix as successful ingestion: inspect the next
stage's result and retained diagnostics too.

## Validate APIs together

Pair isolated boundary tests with a realistic composed flow. Select the flow
that matches the request: parser to durable revision to relationship/consistency,
schema to query/redaction, topology to federation to forwarding, or pinned
providers to evidence analysis. Verify exact identities and intermediate results,
not just a successful exit or HTTP 200. Confirm unavailable and malformed
capabilities fail at the core boundary without publishing partial results.
Parser golden tests must enter `IngestionCoordinator` or the durable CLI to
establish schema acceptance; direct parser output checks alone are insufficient.

If the user asks for model-based validation of a skill, have fresh subagents
**use the changed skill** to implement or diagnose representative tasks in
isolated temporary directories without inherited conversation. Give them only
the task, skill paths, and allowed outputs (plus any user-supplied fixture),
without API hints, implementation steps, test names, or expected assertions.
Explicitly exclude all prior trial artifacts, other agents' outputs, parent
check logs and diagnoses from each trial's allowed inputs, even though agents
share one workspace. A retry must start clean rather than copy or inspect an
earlier attempt. Reading such material invalidates its independence; record
that contamination and rerun cleanly with the same minimal task prompt.
Keep each batch's skill version fixed and record the prompts and skill hashes.
Use the user's requested
model; otherwise preserve the configured model. Assign disjoint files and
include both an individual API task and a combined task. Read their artifacts
and actual test results, fix demonstrated instruction gaps in the skill, and
repeat only the affected task with a fresh agent and the same minimal prompt.
Avoid follow-up coaching that would hide a skill gap. If subagents are unavailable, report that limit and run the
same scenarios locally.

For loading or cache changes, use the map's
[performance boundaries](../../../docs/plugin-api-validation.md#loading-and-performance-boundaries).
For navigation eviction, verify destination size/checksum validation precedes
idle reclamation, missing/changed packs preserve current cache, and active-reader
release during a blocked cold load still reserves the incoming slot. Exercise
validation/load failure, retry, and concurrent close with exact cleanup counts.
Compare cold and warm behavior, including changed inputs and failed or
superseded requests. A faster successful call does not establish unchanged
identity enforcement, archive safety, or browser readiness.
For reported search/import latency, follow the map's
[cold-path measurement checks](../../../docs/plugin-api-validation.md#cold-search-and-import-measurements).
Separate complete user-path timings from instrumented attribution and tiny
microbenchmarks. Check a reused dependency-analysis artifact against changed
source and live targets; a warm cache must still reject those changes.
Exercise exact-type boundaries with equality-spoofing and unhashable
metaclasses, ordinary controls, and unsupported state. Check both public
fingerprints after a callable's behavior changes; a private-helper check or a
direct attribute read alone can miss a callable-global bypass. For projection
fast paths, compare complete safe text and ordered matches, including generic
mappings, subclasses, nested policies, Unicode and numeric distinctions.
For compiled projection policy, check unknown-resource fallback, ancestor and
literal dotted-key handling, policy isolation, output ownership and bounded
metadata retention; a cached plan must not retain event values or runtimes.
Preserve repeated phase occurrences when comparing benchmark results; count
records as well as distinct phase names and include every occurrence in totals.
For import/search cooperation, verify idle and same-thread searches never sleep,
nested/concurrent import scopes survive independent exits, and failures or
cancellation clear activity. Check exact search results and compare both
workloads' latency without relaxing source or invocation-boundary verification.

For combined history changes, exercise cache retirement with an active
reader, same-revision replacement, dense and sparse searches, refinement,
paged layer filters, and cold narrow timeline windows against exact raw
references. Include repeated merged event/source locate and destination-page
requests: fast single-stream queries can conceal a full-stream merge. Check
retained bytes and visited records, not only response limits. The performance
map lists relevant tests and generation commands;
a small fixture establishes correctness, not million-event performance.

For compressed search storage, compare all ordered literal matches with an
exact safe-text reference, including Unicode, NUL, empty needles/documents and
cross-document boundaries. Exercise malformed framing, bounded decompression,
block and corpus digests, format/revision identity, reopen and corruption
fallback. Check that selective refinements decode only candidate blocks and
that small sidecars retain compact storage. Separate these correctness and
work-bound checks from fresh full-corpus size and CPU measurements; prototype
measurements do not establish production performance.

For search reuse across navigation, check released-runtime collectibility,
global byte/entry bounds, concurrent readers, and changed content or projection
under the same revision label. Reopen validation must precede shared-result
reuse. For candidate indexes, compare complete ordered matches and skipped
blocks, including frequent and absent terms; report build/storage cost alongside
query gains and preserve an exact scan when the accelerator is unavailable.
For process-local compressed validation records, verify every current payload
and metadata field against previously validated content on the snapshot actually
used by the reader. Exercise changed bytes with unchanged timestamps, replacement
during opening, corruption in the last block, changed limits, eviction, and cold
process fallback. Separate cached-query reopening from a new term's exact scan;
compact record estimates do not establish total retained RSS.

For timeline/density changes, follow
[zoom-query validation](../../../docs/plugin-api-validation.md#zoom-and-history-query-validation).
Check both coarse summaries and exact drill-down with the same evidence;
separate bounded output from bounded computation, and verify warm-cache
identity, disclosure, cancellation, and concurrent requests.

For frontend state repairs, follow the map's
[state and recovery checks](../../../docs/plugin-api-validation.md#frontend-state-and-recovery).
Wait for asynchronous refreshes before judging retained choices, and exercise
the next successful action after a failed operation through the actual UI.
Include duplicate tree instances, uncached keyboard targets, and invalid input
while an older read is pending. Verify selected presets, focus, popup anchors,
and dependent guidance after the settled render. Use production-normalized
source lanes and server-shaped inferred edges in composed regressions; invented
optional fields can hide an integration mismatch. See the map for these checks.
Exercise actual originating handlers when superseding work; manually advancing
a token cannot prove that slider, selection, or disconnect actions advance it.
Include a slider key or pointer action that leaves its value unchanged.
Include pending repeated reveals followed by Back, pan or hide, concurrent
actions on the same uncached selection, subpixel ranges at both capture
boundaries, and pagination/reopening with expanded details. Check actual marker
and log-row visibility in both axes of the nested and browser viewports, including
sticky labels and headers, not only activeElement identity. In narrow viewports,
verify that hover cards do not intercept their trigger's click and that
markers retain live, instance-specific popup anchors after selection rerenders.
Compare pointer and Enter/Space activation of individual source and review
markers as well as clusters. Check placement after focus scrolling settles in
both the document and nested scrollport, while retaining popup content and
keyboard focus. Check that
normalized/source/review marker centers hit the expected identity, including
two-item groups, cluster boundaries, selected marks and zoom changes. Compare
the same event and resource across lane, log and review popups; preserve finite
and explicitly open-ended durations, and label unavailable history as unknown.
Compare
exact counts with paged detail, and retained-result labels with the applied
request after invalid input. Exercise route-row seeds across directions and
equivalent endpoint descriptors. Distinguish natural browser timing from
controlled delayed-response tests and report both evidence levels.

## Report accurately

Record the API inventory, reproducible findings, edits, commands, pass/fail/skip
counts, and remaining limits. Never turn a declaration inventory or a handful
of passing tests into a claim of exhaustive coverage. Fix demonstrated issues
within scope, preserve unrelated working-tree changes, and complete `AGENTS.md`'s
plug-in documentation drift check before handoff.

For compact indexed-history changes, verify read-only Mapping rows through
generic queries and JSON projections. Check nested ownership, repeatable items
views and UID/ordinal behavior after sorting. For duplicate UIDs, the ordinal
must select canonical-sort-LAST (not FIRST/setdefault), while row lookup must
select arrival-LAST through a sparse compatibility override when needed.
An empty UID must retain row lookup without any ordinal. Independently assert
all three rules using unsorted duplicates and an empty UID; agreement between
row and ordinal lookups alone is insufficient. Use `tests.test_scale_data` alongside the API map history tests;
measure focused construction/projection CPU and retained GC before full-scale
trials. For bounded immutable reuse, verify complete value identity, JSON type
and ordering fidelity (including bool/int/float equality collisions), pool
bounds and isolation, and disposal of load-local pool indexes.
