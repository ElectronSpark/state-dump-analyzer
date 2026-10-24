# Plug-in API validation map

Use this map to choose a contract section and an executable check without
loading the full author guide. Start a new parser with the
[quickstart](plugin-author-quickstart.md); the [contract](plugin-contract.md)
defines semantics and the [author guide](plugin-author-guide.md) explains examples.

Repository skills are available at
[`router-plugin-author`](../.agents/skills/router-plugin-author/SKILL.md) and
[`router-plugin-validate`](../.agents/skills/router-plugin-validate/SKILL.md).
Use the first to implement a plug-in and the second for a requested audit.
These instructions are designed for task-based use and are validated with
GPT-6.1 Sol; they do not set the application's AI provider or model.

## Run a check

From the repository root, use the same Python 3.12 environment for installation,
the validator, and tests:

```text
python -m pip install -e ".[test,web]" -e demo -e state-dump-generator
python scripts/check_plugin_conformance.py --list
python scripts/check_plugin_conformance.py --group foundation
python scripts/check_plugin_conformance.py --group revision --group composition
python scripts/check_plugin_conformance.py --group combined
```

`--list` checks that all required and capability-gated `AnalyzerPlugin` hooks,
all `PluginCapability` members, and the public protocols in `plugin_api.py`,
`runtime.py`, and `normalized_data.py` have a group. It also checks that named
test modules exist. This is declaration coverage, not proof that each method,
descriptor field, failure mode, or combination is behaviorally covered.

`--group` runs the selected existing suites with `unittest`, deduplicating
modules when groups overlap. `--all` runs every group below. The script exits
nonzero on inventory drift or a failed suite. It uses the invoking interpreter,
does not install packages, and does not regenerate the full-scale demo archive.
Integration suites create small synthetic fixtures in temporary directories;
the two-node evidence test uses the minimal status fixture. A pre-existing
demo archive or lock file is not evidence that a check regenerated it.
Small fixture size does not imply a quick run: combined assembly setup and
durable/process integration checks can take several minutes. Use focused
tests and a small golden test for an individual hook; reserve `--all` for a
requested full plug-in audit. Keep the verbose test log when running broad groups.
Full core discovery also includes expensive all-pairs route checks and generator
scans; small inputs alone do not bound their execution time.
For an individual implementation, select relevant module/class/method tests
from the mapped suites with `unittest` and add a small golden test. A group is a
broader integration check, appropriate for a complete surface or shared change.

Prefer `unittest` for fixture plug-ins: pytest assertion rewriting can change
the bytecode checked by executable-identity validation. When using a focused
pytest command, add `--assert=plain -p no:cacheprovider`. Record platform skips
and dependency failures separately from contract failures.

For an isolated durable plug-in trial, put the class and instance in an
importable module and import it from the test or CLI driver. Definitions in an
executing `__main__` module can fail executable-source identity checks. Correct
the import binding rather than weakening the identity boundary.

Parser golden tests should also enter `IngestionCoordinator` or the durable
CLI. Direct parser calls and `validate_plugin` do not establish schema acceptance:
every emitted source type needs a `SourceRecordTypeDescriptor` in
`PluginSchema.source_record_types`. For a durable combined task, assert the
persisted revision, relationships, and findings; a hand-built world verifies
hook composition without verifying durable scheduling.

### Executable identity troubleshooting

Before tests, print `sys.executable` and verify imports required by the selected
suite. For demo/browser checks, this includes `router_dump_analyzer`,
`rsl_demo_plugin`, `fastapi`, and `httpx`. A source-only `PYTHONPATH` does not
supply missing dependencies. On Windows, the repository setup uses the Conda
environment `router-dump-analyzer-demo`; find its interpreter with
`conda env list --json` or the discovery logic in `scripts/launch_demo.ps1` and
use that same executable for CLI, tests, and child processes. On Windows, use
explicit UTF-8 when reading or writing generated source, tests and reports
(`Path.read_text(encoding="utf-8")` and `Path.write_text(..., encoding="utf-8")`);
the default code page may reject Unicode evidence after opening a file for
writing. Inspect an
existing configured environment before installing packages or reporting a
dependency as unavailable. Custom environments remain supported.

First confirm the interpreter and import paths used by both CLI and tests.
Keep the plug-in in an importable module and disable pytest assertion rewriting
as described above. If unchanged imported code still fails source identity,
retry the affected command with a fresh, writable cache directory dedicated to
that interpreter and run:

```text
python -X pycache_prefix=.runtime/plugin-check-cache -m unittest tests.test_plugin_authoring_docs -v
```

Use a new directory name if this path already contains another run's cache.
For a plug-in-specific failure, replace the test target with that trial's
command. For the durable CLI or runners that launch child Python processes,
set `PYTHONPYCACHEPREFIX` in the environment before launching the command; a
parent-only `-X` setting may not reach the worker. For example, in PowerShell:

```powershell
$env:PYTHONPYCACHEPREFIX = Join-Path (Get-Location).Path '.runtime/plugin-worker-check-cache'
python -m unittest tests.test_plugin_authoring_docs -v
```

Use a fresh directory for this run and restore the previous environment value
afterward. These settings redirect bytecode reads and writes away from source-tree caches;
`-B`/`PYTHONDONTWRITEBYTECODE` only prevents writes. See Python's
[cache-prefix documentation](https://docs.python.org/3.12/library/sys.html#sys.pycache_prefix)
and [bytecode-write option](https://docs.python.org/3.12/using/cmdline.html#cmdoption-B).
Keep identity verification enabled and preserve shared caches. A successful
registration only clears that stage: check ingestion and publication afterward,
and inspect retained failure diagnostics when the public job error is generic.

For isolated Windows tests, direct `TEMP` and `TMP` to a writable task directory
before launching child processes. If HTTP test setup stalls, capture a bounded
stack trace before attributing it to fixture generation. A stack in
`socket.accept` / `_fallback_socketpair` while constructing the Proactor loop
can be an execution-environment restriction; retry the same bounded test with
the required execution permission instead of changing application behavior.

## Loading and performance boundaries

Measure the changed path with a fixed fixture and interpreter. Distinguish
process-cold and warm provider calls from fixture generation, HTTP transport,
and time to a usable browser view. Use a separate profiler run for attribution;
instrumented seconds are not request latency. The
[topology/route profiler](../scripts/profile_topology_routes.py) and its
[method](topology-route-profile.md) cover direct providers. A small fixture
does not establish full-scale archive performance.

For cursor-refresh spikes, time the actual graph, resource, dashboard and topology
requests separately, then repeat an identical late-cursor request. Record selected
views, limits and time basis. Profile clock-uncertainty probes and relationship
history traversal before adding caches: a bounded result page need not bound
intermediate work. Test disconnect propagation separately; an aborted browser
fetch or progress-poll count does not attribute server CPU or prove cancellation.
Keep resource-search text and selected kind explicit in cursor benchmarks. Compare
matched fresh timestamps with search empty and active, plus same-time cache hits;
separate first lazy-history materialization from later reconstruction. Preserve
ordered rows, total/counts-by-kind, provider metadata and disclosure when reducing
projection work. Kind filtering cannot move ahead of search if it changes the
cross-kind counts, and reuse must not skip the final safe search-text projection.

When optimizing relationship sampling, preserve the original ordered probe set
and final wire output, including same-identity history precedence. The indexed
path resolves active last writers before relation/presence filtering; a callback
reader's returned rows are filtered before duplicate identity resolution. Do not
silently unify those behaviors or add previously unsampled transition boundaries.
Validate both interval bounds once per visited history entry, even for excluded
or out-of-window rows. Inclusive starts, exclusive ends, unbounded endpoints,
unknown/deleted presence, center-or-first representatives, and independent
relationship/connectivity limits need equivalence checks. Count visited entries
and timestamp parsing separately from returned rows; measure temporary maps as
well as retained memory. Run `tests.test_temporal_relationship_probes`,
`tests.test_reconstruction_truth` and `tests.test_provider_execution_boundaries`
for the frozen scan oracle, deterministic boundary cases and provider behavior.
The probe suite is also included in the presentation conformance group.

Core owns execution identity, request cancellation, and public loading state.
A compilation cache may retain bounded immutable artifacts derived from exact
source/compiler inputs; it must not retain a trust decision or replace fresh
source reads, live dependency inspection, or before/after invocation checks.
Exercise warm-cache source changes, runtime mutations, and eviction through
the same core callers as cold execution. Use `tests.test_plugin_identity`,
`tests.test_plugin_identity_runtime_imports`, `tests.test_capability_router`,
and `tests.test_provider_execution_boundaries` for these boundaries.

Repeated path resolution within one attestation uses a bounded cache of exact
string candidate tuples. Its final provenance pass resolves each distinct path
again using a separate temporary map; neither map crosses fingerprint calls or
before/after invocation checks. Preserve per-object/module comparisons and fresh
source-byte/file-identity reads. Test path retargeting after source inspection,
same-byte replacement, deletion, live mutation and uncached string subclasses.
Measure filesystem calls separately from provider work before adding result caches.

For archive changes, retain traversal of trailing members and rejection of
unsafe names, duplicate members, nonregular entries, size/hash mismatches,
and incorrect projection identity. Validate reordered archives as well as
canonical generator output with `tests.test_demo_assembly_store` and
`tests.test_demo_archive_safety`. Lazy loading may defer work but must not
silently weaken validation or change the accepted data.

The demo assembly adapter first checks the prepared destination pack's bounded
compressed size and SHA-256 against the assembly descriptor using streaming reads,
without decompressing it again. Missing or changed packs preserve the existing
cache. It then reserves a cold-load cache slot by closing idle LRU
generations before calling the dataset loader. Releases during materialization
also respect that reservation. Active leases remain usable and
can temporarily exceed the cache bound. Verify reclamation inside the next
loader, including a weak reference to the retired payload; checking the final
cache size alone misses the transient overlap. Resolve unknown destinations
before eviction. A failed load may discard an idle cached generation, but its
validated private archive must remain available for retry and navigation back.
Exercise concurrent cache hits, releases, shutdown, and close-once behavior
with `python -m unittest tests.test_demo_assembly_store tests.test_demo_archive_safety -q`.

For combined browser flows, distinguish core ingestion from durable
materialization and the configured startup runtime. Test slow and failed
secondary requests, cancellation, superseded responses, and partial rendering;
only the current revision/context may publish. Report actual loading stages
without guessed percentages. Browser timeout bounds waiting and does not
prove synchronous backend execution stopped. Run the relevant frontend tests
and browse the resulting integration before claiming UI readiness.

Read-only runtime routes connect disconnects to request-local core checkpoints,
including graph, resource, dashboard, source, topology and search scans. Durable
mutations do not inherit this scope. Shared cold runtime materialization remains
noninterruptible; distinguish it from a cancellable worker scan. Cancellation
must release leases and search-build waiters without retaining a partial cache
or permanently poisoning the next request. Exercise real ASGI receive messages,
mid-scan aborts and independent readers with
`python -m unittest tests.test_read_query_cancellation tests.test_zoom_cancellation -v`.

The Windows CLI owns a Proactor loop that handles peer-reset socket shutdown
while retaining CPython's existing close/detach cleanup. Its narrow private
transport-construction hooks preserve the exact socket object and descriptor;
rewrapping an IOCP-registered descriptor can fail on outgoing TCP/TLS. Validate
normal and reset closes, unrelated errors, custom-socket rejection, over 512
connections, TLS, subprocesses and actual CLI lifespan shutdown with
`python -m unittest tests.test_windows_event_loop tests.test_uvicorn_compatibility -v`.
Do not replace this evidence with traceback filtering or a global asyncio patch.

The core safe-text sidecar uses versioned SQLite storage. Plain corpora below
1 MiB retain 4 KiB pages; larger plain corpora and compressed corpora use
64 KiB pages. Above the eager-candidate character budget (64 × 1024² characters by default),
or once 65,536 buffered documents are reached, storage switches to zlib level-1
blocks. Small corpora retain the optional trigram accelerator. Compression
preserves complete UTF-8 documents and ordinals; matching never crosses document
boundaries. Cached refinements fetch and decompress only blocks containing
candidate ordinals, after scanning their bounded headers. The query-result
cache and exact disclosure projection remain shared across storage modes.

Block framing targets 256 KiB, allows a single document up to the configured
document-byte limit, and caps each block at 65,536 documents. Full validation checks
contiguous ordinals, counts, UTF-8, exact framing, bounded decompression, per-block
SHA-256 and the complete canonical document digest against revision identity.
Cold compressed validation decodes each bounded block once and rejects document
boundaries inside UTF-8 scalars, then hashes original framed bytes. Empty frames,
invalid boundaries and trailing data remain invalid even when concatenation
decodes. The canonical digest and storage format are unchanged.
Queries pin validated block framing, raw digests and compressed-payload SHA-256
hashes to the generation. They recheck generation/framing metadata and verify
compressed bytes against those pins before bounded decompression, preserving
the validated UTF-8 corpus without rehashing its larger raw representation.
Navigation may reuse the process-local compressed validation facts described
below, after freshly hashing all compressed content in a read transaction.
Unreadable storage falls back to the safe projection. Publication remains atomic, and a
reader does not unlink another process's published cache. Old format versions
are derived caches and are rebuilt. Exercise `CompressedHistorySearchTests`
alongside the existing search algorithm suite when changing this storage path.

```text
python -m unittest tests.test_history_search_core.CompressedHistorySearchTests -v
```

Derived density, timeline, event-union, and redacted-event query caches belong
to the exact immutable history generation. A service must not keep a retired
generation alive through cached query values. Live leases may continue using
that generation until release; a replacement with the same revision string
must use its own derived state. Adapters that cannot carry generation-local
state receive request-local derived state instead of a process-global cache.

`HistorySearchCorpus.query()` returns a read-only `Sequence[int]` of exact,
ordered document ordinals. Consumers use length, indexing, iteration, and
bounded slices rather than assuming an `array` or copying the whole result.
Core chooses sparse ordinals, complement ordinals, or a bitmap with rank
metadata; retained query results are bounded by query count and encoded bytes
(`max_cached_bytes`, defaulting to four times `max_cached_ordinals`). An
oversized result remains queryable without being retained. Candidate refinement
must preserve literal case-folded substring semantics: only a cached shorter
needle contained in the new needle can safely supply candidates, and every
candidate still receives the exact substring check. Cold matching can share
corpus construction or sidecar validation scans, but results publish only after
complete identity, count, digest, and candidate-index validation succeeds.

For search-cache reuse across navigation, distinguish an immutable validated
corpus from the runtime that owns event objects. A bounded core cache may retain
compact exact postings or derived index metadata across runtime retirement only
when their key binds the full corpus content, projection semantics and index
format. A revision label or path alone is insufficient. Reopening must complete
corpus validation before sharing results; never cache authorization
or executable trust. Check global entry/byte budgets (including keys), eviction,
concurrent readers, distinct revisions with the same label, corruption fallback,
and weak-reference collection of retired runtimes/builders.

The core's process-local retired-result cache is bounded to 128 entries and
16 MiB including keys and bookkeeping. `close()` publishes only the compact
results still retained by that corpus; event rows and builders are released.
Reopened corpora validate first, then may reuse results under the full content,
projection, format and count identity. Non-exact string keys are not shared;
subclass conversion, equality or hashing must not alter literal cache identity.
Changed sidecar stamps suppress shared lookup. This cache does not persist
between processes; result reuse alone does not avoid reopen validation.
Sharing is limited to successfully built or validated persistent sidecars,
which already compute a complete corpus digest. Memory-only construction and
disk-failure fallback keep their original no-hash path and never publish shared
results; hashing all their text just for reuse adds avoidable first-query CPU.
Exercise `tests.test_history_search_reuse` together with both existing search
suites and the assembly navigation checks.

A bounded process-local validation record may avoid repeating decompression
only for previously fully validated compressed content. Freshly hash every
compressed payload and compare exact ordered framing, metadata and the current
projection identity with that record. Recheck current document/character/byte
bounds, including bounds on individual documents previously validated. A changed
limit that cannot be established from the record requires full validation.
Do not accept a digest merely because it is stored alongside the payload.
Metadata, payload checks and subsequent reads must refer to the same stable
generation; SQLite `immutable=1` is an assertion, not a lock or integrity proof.
Bind the snapshot lifetime explicitly and fail/revalidate on replacement or
mutation. Entries retain compact immutable validation facts, never event rows,
builders, runtimes, authorization or executable trust. Bound total bytes and
entries including keys/bookkeeping; eviction must be safe for active readers.
Unknown content, cold processes and cache misses retain the complete validator
and corruption fallback. Exercise same-size changes with restored timestamps,
last-block corruption, replacement during open, revised limits, concurrent
readers/close and retirement collection. Measure first-process validation and
navigation reuse separately, with cached and uncached query terms.

The implementation bounds these facts to 128 entries and 256 KiB including
fingerprint keys and bookkeeping. Each record retains only the previously
validated maximum document-byte length under a fingerprint of complete metadata,
ordered block framing, raw-digest metadata and freshly hashed compressed bytes.
It reconstructs reader-owned block pins while checking that fingerprint; it does
not keep a global copy of the block map. Read transactions bind metadata and
payload scans, and pre/post file stamps include file identity to reject observed
replacement. No connection or file lock survives validation or a query. Cached
first queries reuse compact results directly; new terms still scan exact framed
bytes. Run `tests.test_history_search_validation` with the existing storage,
reuse and navigation suites.

An optional large-corpus candidate index must preserve the compressed corpus
and exact UTF-8 literal matching. Candidates are a superset, followed by exact
verification within document boundaries. Measure index construction CPU and peak
memory, retained/disk bytes, and blocks visited for rare, common, absent, short,
Unicode and NUL-containing terms. Block indexes can be ineffective when every
block contains a match; use measured selectivity to retain scanning when cheaper.
Compare compact document-level postings only if block pruning is insufficient
for the target workload. Do not increase the small-corpus FTS threshold without
measuring its impact on initial readiness and storage.

Use `scripts/profile_history_search_indexes.py --sidecar <compressed-sidecar>`
for a bounded offline comparison of block trigrams and document postings. Its
defaults sample at most 32 blocks, 16 MiB of raw frames and 50,000 documents;
it leaves production indexing unchanged. The report separates build, candidate
selection and exact compressed-block verification. Serialized posting sizes
are estimates: queries use resident bitsets/arrays, and the experiment excludes
full-corpus validation, SQLite query I/O and production peak RSS. Run
`python -m unittest tests.test_profile_history_search_indexes -v` after changing
the comparison script. Full-scale CPU and memory still require the actual
production query/navigation path.

Indexed history accepts read-only event mappings and sequences. The generated
demo shares its UID ordinal index with a compact row lookup view; the
[storage contract](api-contract.md#windowed-scale-history) describes ownership and
duplicate-UID compatibility. Reuse complete owned immutable values only within
bounded load/generation-local pools, and preserve exact JSON types and ordering;
include equality-collision, pool-isolation and retained-GC checks when measuring
construction CPU. Ordinary parser emissions need no new hook.

A compatibility history adapter may provide `ordered_events_by_resource` as
an optional accelerator containing the same complete per-resource event
sequences in canonical temporal order. Core can bisect these sequences before
building a cold timeline window and count unique events from the selected
window, preserving inclusive nanosecond bounds and stable event identity.
This is not a new capability hook or a requirement for ordinary parsers.
Adapters without it retain the existing complete-history fallback. Treat the
sequences as immutable for the lifetime of their history generation.

Use the combined regressions for generation retirement, shallow-copy isolation,
request-local fallback, cold ordered windows, window-local event unions, and
paged layer-filter reuse, alongside exact search and archive lifecycle checks:

```text
python -m unittest tests.test_history_query_algorithms tests.test_history_search_algorithms tests.test_history_search_core tests.test_zoom_timeline tests.test_demo_assembly_store tests.test_demo_archive_safety -v
```

For skill trials requested by the user, exercise the changed author/validator
skills on a combined bounded synthetic lifecycle, search, and timeline flow.
Include active leases across eviction, released-generation collectibility,
replacement identity, sparse/dense refinement, bounded pages, and exact narrow
or same-timestamp windows. Record skill hashes and compare outputs with raw
reference records; count visits and retained bytes. A small trial establishes
correctness and work boundaries, not full-scale latency or peak memory. Report
full-scale generation, deep validation, cold loading, and warm query costs
separately when those measurements are available.

### Cold search and import measurements

Use a fresh process and empty search-cache directory for the first-query path.
Record the process's effective cache path and search-cache overrides before
classifying a delay as sidecar reopening; a sidecar in another directory is not
evidence of reuse. Trace validation and construction separately, and isolate
concurrent temporal work from first-use search before attributing a stall.
The browser deployment defers search-corpus construction; an API-only warmup
can build it before a timer starts. Include the exact client-safe redaction and
JSON projection, not just matching against an already constructed sidecar.
Compare ordered matches, sidecar identity, cold/warm CPU, retained memory, and
navigation peaks on the same fixture. Record browser completion separately
from backend timings; process CPU excludes separate import workers.
Preserve every phase occurrence in comparison scripts: repeated page requests
can share a phase name, so a dictionary keyed only by that name silently drops
measurements. Compare ordered phase sequences or use name-plus-occurrence keys.

Measure tiny durable imports both alone and, when relevant to the finding,
alongside cold search. Use the actual deployment composition, parser choice,
worker isolation, and retained processing-event timestamps. Profile fixed
registration, live executable identity, child startup, ingestion, and publication
separately before attributing a delay to input size or a particular stage.
Microbenchmark gains do not establish end-to-end improvement.
If imports slow only during heavy queries, separate parent thread CPU from wall
time, child work, and GC before attributing the delay. Profile overhead is not
request latency. Scheduling experiments must measure both import responsiveness
and search CPU/wall time; a faster import alone does not justify slowing every
idle search or weakening invocation-boundary checks.
The internal core import/search cooperation is exercised by
`tests.test_import_scheduling`: claimed durable stages own scoped activity,
and cold corpus construction offers a short scheduling window only when a
different thread has an active import. Verify nested/concurrent scope cleanup,
every stage's error/cancellation exit, exact results, capacity failures, and
that the activity lock is released before a pause. Idle and same-thread searches
must not sleep. This is core scheduling, not a plug-in hook or an identity cache.

Dependency-disassembly reuse must retain only immutable derived names/paths,
bounded by entries and bytes. Key by exact weak code identity rather than
structural code equality; source reads, dependency resolution, target mutation
checks, and invocation-boundary verification still run. Exercise collection,
eviction, and live changes with `tests.test_plugin_identity_runtime_imports`.
The `foundation` conformance group includes that module and
`tests.test_plugin_identity`.

Exact built-in type classification must use object identity, not equality-based
set/tuple membership. A custom metaclass can spoof equality/hash or be
unhashable. Audit direct guards and aliases to type groups, including hidden
built-ins and descriptor classification. Exercise
`executable_callable_fingerprint` and `executable_module_target_fingerprint`
with a source-backed callback invoking a mutable callable global, mutate its
state, and verify changed fingerprints or the declared fail-closed error.
Include ordinary-class and real-container controls and unsupported opaque
state. A direct attribute read may independently bind state and conceal a
broken callable-global path; it is not a substitute for invocation coverage.

Safe-text accelerators may cache bounded policy-path transitions, not mutable
event projections. Preserve ancestor-sensitive paths, policy isolation, exact
JSON encoding and case folding. Check the final corpus against an independent
safe-projection reference. Index-build progress should advance during work,
remain path/text-free, and never substitute a count for integrity validation.
Compile the effective policy once for an event and pass it through nested
projection instead of repeatedly converting field sets. Bounded generation-local
policy combinations may reuse unions and condition decisions, but must include
conservative unresolved/unknown-kind handling and retain no event values. Avoid
temporary one-property wrappers through a path-aware helper only when it applies
the same ancestor/dotted-key transition before recursion. Hoist constant field
sets and preserve exact scalar/subclass semantics when bypassing recursive calls.
Check complete output ownership, policy mutation/isolation and retained key bytes.
Scalar/dictionary fast paths must retain generic Mapping and subclass fallback,
conservative unresolved-kind redaction, nested sensitive-path semantics, and
exact JSON types. Include metaclass equality attacks, Unicode/NUL, and numeric
distinctions in differential checks. Validate complete document digests and all
ordered sparse/dense/absent matches rather than only the first result page.
Measure the implemented production path again: a monkeypatched prototype's
timing does not establish loaded RSS or A-to-B-to-A navigation peaks.
Relevant tests are `tests.test_safe_projection_fast_paths` (also in the
`runtime` conformance group), `tests.test_normalized_data_service`,
`tests.test_revision_queries`, `tests.test_history_search_core`, and
`tests.test_load_progress`.

## Frontend state and recovery

Generic frontend behavior remains core-owned. Preserve an explicit user filter
when refreshed data rediscovers existing options; distinguish discovery defaults
from intentional reveal actions. Check the settled response after zoom or pan,
not only the immediate render before asynchronous data arrives.

Lane presets and explicit custom choices are different state. A selection or
reveal must preserve the current preset's intent, rather than revive an old
custom set; every layout must honor applicable layer and resource visibility.
Guard a navigation intent across awaits and deferred focus/scroll callbacks,
including newer targets that are already loaded and explicit clear actions.
Begin ownership before toolbar selection resolution. Cursor input and newer
log selection must invalidate the relevant pending navigation; check again
on cursor key or pointer interaction even when its value does not change, and
after page loading and immediately before deferred focus. Test actual handlers,
not a simulated token increment. Capture the existing review connection token
before correlation preparation and reject a result after disconnect/reconnect.
Rejecting stale query data alone does not prevent a stale continuation. Conversely,
guarding only the continuation still allows an obsolete payload to replace the
current lanes. Exercise the composed request, selection and normalization path.
Keep navigation authority separate from ordinary window refinement: selecting an
already-loaded resource must not strand an unrelated zoom request. If that request's
resource/root context changes, refresh the current context before applying it.

When a render replaces interactive elements, preserve the activated control's
stable identity and its containing tree/module/device instance. An event UID
plus resource ID is not unique when the same resource appears in several tree
branches. Restore focus without stealing it from a newer user action, and keep
popups anchored to the same instance.

Passive pinned-inspector restoration must not repeat activation's focus transfer.
Type multiple characters into a graph filter with a pin open, then repeat without
the pin. Inspect the active element after each redraw. For Fabric inspectors,
reconcile visibility on graph pan/zoom/drag and page scroll against that graph's
viewport and sticky controls, including partial visibility and dismissed-card
non-revival after Fit.

Selection can synchronously replace a timeline marker before its activation
handler opens a popup. Reacquire the anchor through the existing instance key
after selection, including single source and review markers, without falling
back to detached DOM. Compare pointer and Enter/Space input and duplicate
source presets; working cluster activation does not establish single-marker
behavior.

A live anchor can still move after opening, including during native focus
scrolling. Compare opening and settled marker/card rectangles with document
and nested scroll offsets. Fixed-position cards must follow that movement
without replacing their contents, resetting detail scroll or losing keyboard
focus. A stationary activation control or a single animation-frame delay does
not establish correct placement throughout scrolling.

Native keyboard focus can begin smooth scrolling while its target is still
fully outside the viewport. Settle the intentional timeline focus reveal before
opening a popup or dismissing it for clipping. Keep nearest alignment for visible
targets and preserve the virtual log's separately calculated scroll position.
Native nearest alignment can still place an upward target behind the sticky
header or a horizontal target behind its lane label. Reuse timeline reveal
correction for that occlusion, leaving fully and partially visible targets in
place. Validate Enter/Space starting above and below the viewport and behind a
lane label, including individual source markers; then repeat from visible and
partially visible targets. Synthetic rectangles alone do not establish native
focus/scroll ordering.

Passive focus restoration after a render is separate from an intentional reveal.
Calling `focus({preventScroll: true})` still runs focus handlers, so a handler
must not override the saved scroll during that restoration. Focus a density bin,
wheel its row out of view, and wait for density replacement; repeat with a full
timeline rerender. Verify offsets after the restoration animation frame, keep
clipped popups dismissed, and confirm a later explicit focus still reveals its
target. A newer user focus move must continue to supersede the repair.

Connection to the DOM is not visibility. Intersect a popup anchor with the
document and its own nested client viewport, accounting for sticky headers and
lane labels (or the log's table header). Dismiss fully clipped anchors and keep
partially visible cards within the viewport. Scroll in both axes, click Lanes
after the anchor leaves view, then scroll back: an old pinned card must not
intercept that click or revive. Verify pointer and native Enter/Space activation
after reveal; clipping must not strand a valid newly focused target. Avoid using
timeline bounds for an anchor in a different component.
Include the single-node correlation card: its graph, relationship-index and
resource-table anchors have different clipping boundaries. A captured page scroll
must retire an off-screen pin before it covers Timeline Actions; scrolling inside
the card must preserve its content. Test partial visibility behind the sticky
header and passive re-entry as controls.

Also change layout without scrolling: remove a preceding lane, disable the
popup's own preset, or collapse a containing resource tree. Reconcile the live
anchor after rendering and close cards whose instance disappeared. Opening a
picker must retire an older inspection overlay before it can intercept the new
controls; increasing stacking order alone does not resolve competing ownership.
Change and clear the selected range while source and normalized cluster cards
remain open. Update their range classes and labels in place from each displayed
entry's timestamp, retaining focus, detail scroll, and loaded pages. Reopening a
card can hide stale derived facts and is only a comparison control. Compare each
stream with its own fresh rendering and contract; do not invent identical label
conventions across source and normalized cards.

For virtual logs, carry the latest
keyboard destination through an uncached page response and cover Home/End as
well as Arrow keys; an animation-frame retry alone may precede data arrival.
Source-preset controls need the same focus preservation as resource checkboxes.
Pagination within an unchanged query should preserve group disclosure, expanded
relationship identities and keyboard focus, including the final page.
Check dialog reopen and settled asynchronous rerenders too. Reveal the actual
destination marker or log row, rather than only its containing lane or section.
Check both horizontal and vertical bounds against the nested scrollport and
browser viewport after settling; account for sticky lane labels and headers.
An in-window timestamp or `preventScroll` focus does not establish visibility.
Include a timeline-to-log-to-timeline round trip with tall wrapped log controls
and a clipped horizontal track. Nested native controls must retain their keyboard action
instead of bubbling into a row-selection shortcut. A rejected cap-limited
checkbox change must restore its checked state.
At narrow viewport widths, check the hit target beneath hover cards as well:
an inspection card must not cover and intercept its own jump control. Keep
overflowing facts scrollable and reset any size constraint on the next open.
For dense timelines, hit-test adjacent normalized, source and review marker centers
and compare pointer and keyboard drill-down identities, including selected marks.
Reuse the same spacing calculation across renderers. Include two nearby review
items and groups spanning the bounded cluster size; exact drill-down must retain
every identity. Keep counts/IDs intact
when shrinking glyphs, restore their presentation on zoom, and retain equal-time
evidence; constrain rotated marks as well as clusters.
Compare the same event's same resource effect in lane, log and review popups.
Reuse known per-resource duration and operation from the loaded mark. Distinguish
unloaded/unknown duration from explicit open-ended evidence, and test finite,
zero and open-ended values after changing loaded lanes. A raw event entry alone
does not establish when its affected resource next changes state.

Exercise normalized source-lane construction together with lookup, hover and
reveal. Display clusters may be derived from marks instead of stored on the
lane; test a source in a later lane and one absent from current lanes. Keep
untimed records explicitly untimed.
Repeated reveals while data is pending must reuse the target's lane allocation,
including near capacity. Validate a custom regex with core before retaining its
rule or clearing the form; rejection must not poison later timeline requests.
Use the existing server policy instead of maintaining another regex grammar.
Use the exact core source-record UID selector for a single-record jump. A regex
over record text can match thousands of references before the target itself.
Combine supplied filters, and test collisions in messages plus capped results.
Keep newer form input intact if validation finishes after it changes.
If staged validation replaces a pending viewport read, recover that read when
the candidate is discarded, without canceling a newer request.

Exercise typed ranges narrower than one pixel at both capture ends. Pointer
and keyboard adjustments must remain ordered and inside the capture, without
moving against the requested direction to enforce a visual minimum. Check the
actual summary request as well as formatted fields, which may hide clamping.
During a pending range query, start and cancel a new brush after the old query
settles. Restore the previous range's result or issue its read again; never
restore an orphaned loading placeholder. An unchanged range should reuse its
current result or pending request while still superseding older navigation.
For full-capture summaries, count all events but project only bounded detail;
verify omitted-tail counts, redaction, generic mappings and inclusive bounds.

Validate requests before sending them, but invalidate older response authority
when a newer user intent fails validation. Cover enabled change handlers while
submit is disabled. Programmatic form seeding must update dependent guidance
and controls, not just values. Render explicit edge direction independently
of descriptor availability; inference-rule identity is not a relationship type.
Unknown vocabulary must remain honest without discarding other declared facts.
Keep displayed clock policy and endpoint labels bound to the applied result
after invalid controls or a failed request. Route-row seeds must retain logical
endpoint descriptors, update direction-dependent controls and clear obsolete
errors. Compare canonical start identity rather than incidental descriptor
shape. Missing resolution and traversal-budget exhaustion are not evidence of
disagreement; withdrawn candidates must not invalidate an active path.

At scale, bound combined relationship glyphs across the whole visible window,
disclose sampling and recover exact narrow-window detail. Preview lengths are
not exact cluster or selected-range counts. Repeated navigation must also
retire old event/source/detail cache entries while protecting current lanes,
selection and open detail; a small DOM alone does not establish bounded memory.

Cancel superseded read requests where the transport supports it and retain
generation checks for already-settled work. Do not report browser cancellation
as proof that backend CPU work stopped without a cooperative cancellation check.
Cover disconnects before and during body upload as well as after query work
starts; an early abort should use the existing cancellation boundary.

Form resets restore values but not dynamically assigned validity constraints.
Keep conditional visibility and native validation synchronized on initial load,
reset, reconnect and clear. Exercise a real submit path after those transitions;
a controller-only test cannot detect a hidden required field blocking submission.
Browser history may restore text without dispatching input events. After Back,
wait for reconstruction and compare all visible filters with the actual rows;
reconcile controls with the existing authoritative state rather than introducing
a second persistence scheme. Include clear/retype and a BFCache-style retained
state control. For SVG/HTML graph overlays, compare their rendered dimensions
and coordinate transforms in compact layouts as well as after drag, Reset and
1:1. Check SVG fragment IDs against the whole document, and long route statuses
against direction-label rectangles in both path modes.
Compare correlation from graph nodes/edges and resolution steps in both trace
directions, including decorative edge labels. An executing hop's member must
come from the validated node context even when its evidence cites another node;
preserve that evidence's own attribution rather than relabeling it as local.
Keep path-scoped service context visually separate from forwarding nodes:
a service carried over a path does not establish that every transit node
participates in that service. Correlation anchors and path endpoints are not
membership evidence. Check context details and path emphasis in both graph modes.
Keep service-context rendering tied to route changes, not graph geometry updates.
Open its details immediately after switching Focused/All paths and after layout
transitions settle; the live trigger and keyboard focus must survive resize-only
redraws. Scroll a pinned service trigger outside the viewport and behind the
sticky header, with a partially visible trigger as a control. Scrolling inside
the popup must preserve it. After reading lower facts, focus another control
and return the pointer to the same service label: passive re-entry must retain
popup scroll and external focus. Direction, path, and trace replacement must
still clear obsolete service details, including reused presentation group IDs.

Also check narrow width independently of short height. A preview can fit inside
the viewport while covering its trigger or adjacent graph-mode controls. Hit-test
the actual button center with the card open, compare pointer with Enter/Space,
and repeat without the card. When neither side fits, validate vertical placement
and internal scrolling without losing the existing clipping/focus behavior.

### Historical route and correlation checks

For historical routes, compare the applied frozen member basis with each route
row and forwarding decision's validity, including the full clock uncertainty
interval. Exercise direct traces and table-seeded traces before, within and after
validity; a filtered table alone does not close a trace bypass. Cross-check a
typed point-to-point circuit against its local interface at down and restored
times, then repeat past-present-past. Assert that the traced segment actually
crosses the changed circuit; parallel routes involving both nodes are insufficient.
Single-node native cursor offsets and fabric UTC times can have different origins.
Use exact timestamps and failed/stale events as controls. Graph and resource-table
refreshes settle independently, so save both settled results before comparing them.
Use unequal clock offsets to verify that each continuation's observation is in
the executing node's domain, independently of its evidence owner's validity.
Regenerate persisted projections after producer changes; changing code does not
repair an already-generated archive. For bounded or representative correlations,
an omitted focus means the response does not cover it, not that it has no edges.
Compare full/focused scope, explicit inactive roots, and unknown roots without
raising graph bounds to hide missing coverage.

Compare persisted relationship intervals against per-service attachment events,
including a later service sharing an already-existing ES and primary endpoint.
At one nanosecond before attachment, its membership and active-path edges must
be absent even when both endpoint resources exist. Check the exact event and
rewind, with table home mode as an independent control. Derive event affected
service counts from actual membership, including uneven small layouts.

For route-form compatibility, edit VRF, family and type in different orders and
verify both settled controls and the submitted request. Preserve the explicitly
changed advertised field while reconciling dependent controls. For narrow
correlation graphs, measure card/label bounds and actual pointer hit targets;
SVG label presence or successful Enter activation does not establish clickability.
Repeat after horizontal scroll, full/focused switching and cursor changes.

The generated adapter and core boundary are exercised by:

```text
python -m unittest tests.test_route_history_validity tests.test_generated_assembly_api_integration -v
```

These are conformance checks for the existing generated example, not new parser
hooks. Use the same saved fixture in browser follow-up and compare the link with
its local single-node status.

### Request recovery

Read failures must settle local pending-operation state without replaying a
mutation or letting an old request overwrite a newer generation. Verify that a
failed lookup clears stale report authority and permits the appropriate next
action, while an accepted active run retains its execution/cancellation rules.
A successful management action should replace earlier error feedback. Test the
failure-to-success transition through the installed event handlers.

Run `npm --prefix frontend run check` after frontend changes. Keep transport or
sandbox failures distinct from assertions; if loopback sockets are denied, rerun
the affected checks with the necessary local execution permission. Browser
validation must load the changed assets and record the final visible state.

For a browser finding, verify both failure feedback and the next successful
action. Check document overflow against the actual viewport and confirm local
progress is cleared after rejection. Treat a modifier-click failure seen only
through an automation tool as unconfirmed until the input path is reproduced;
unit coverage of selection logic alone does not prove native pointer delivery.
Keep upstream transport cleanup failures distinct from application exceptions;
blanket exception suppression is not a fix.

## Zoom and history query validation

Timeline and density aggregation are core services, not new plug-in hooks.
Use `RevisionQueryService` with an explicitly scoped dataset and optional
`IndexedHistory`; the HTTP adapter supplies revision authority and cancellation.
The API contract's [timeline](api-contract.md#6-timeline-and-cluster-expansion)
and density sections describe response semantics. Ordinary parsers still emit
normalized observations/events and schema descriptors through ingestion.

Validate wide, narrow, empty, and same-timestamp windows against the same raw
synthetic evidence. Keep integer nanosecond boundaries exact, including negative
coordinates and inclusive event endpoints. Preserve stable temporal ordering,
selected events, count/failure totals and redaction through cluster drill-down.
State summaries are incomplete detail, never evidence that a resource was absent
or healthy. Type summaries must retain enough information for exact merged
counts; combining only each child's top types is not exact.

A bounded response alone does not establish scalability. Count event visits,
detail projections, and index operations for cold and warm calls. Exercise a
busy single resource as well as many lanes. Keep caches bounded by retained
work/size and entries, scoped to live immutable revision identity, isolated
across revision replacement, and safe under concurrent calls. Cancellation
must not publish partial results or incomplete indexes. A browser abort only
stops backend work where a cooperative checkpoint observes the disconnect.

For mixed event/source history, compare unfiltered indexed pages and locate
results with the exact fallback, including tied timestamps, range-first groups,
untimed sources, duplicate/empty UIDs, and filtered queries. Reuse ordered
indexes rather than rebuilding all normalized candidates for a small page.
Count indexed access and projections for both locate and the destination page,
including deep offsets. Benchmark repeated normalized-only, source-only and
merged requests separately, then the complete jump; a fast constituent stream
does not establish a fast merge. Report transient peak and retained memory
alongside CPU, without attributing service timings to browser input-to-paint.

Use these focused checks after changes to this path:

```text
python -m unittest tests.test_zoom_timeline tests.test_zoom_density tests.test_zoom_cancellation tests.test_revision_queries tests.test_timeline_cluster_detail tests.test_scale_history_stream_api tests.test_scale_history_frontend -v
npm --prefix frontend run check
```

Add a small combined scenario entering the real query/HTTP boundary. For parser
work, ingest the fixture before querying it. Validate exact revision identity,
coarse counts, detail membership, and sensitive-field omission, not only HTTP
success. Browser checks should include rapid zoom/pan, a late old response,
revision replacement, retained selection, and honest cached/refining indicators.
Report operation-count evidence separately from wall time and peak memory;
a million timestamps alone does not benchmark a million rich event objects.
Include both low and high event-type cardinality: per-bin bisection can beat a
full sweep for dense types but regress when almost every event has a distinct
type. Also check the unindexed fallback independently; rebuilding transient
per-resource lists can defeat cache identity and multiply full-history scans.

## Every analyzer hook

Exact signatures and typed values are in
[`plugin_api.py`](../src/router_dump_analyzer/plugin_api.py) and its sibling
`.pyi`. Required hooks and capability declarations are checked by the
[author validator](../src/router_dump_analyzer/plugin_validation.py).

| API | Gate and caller | Conformance group |
|---|---|---|
| `manifest`, `describe()` | Required identity and `PluginSchema`; validator/registration | `foundation` |
| `probe()` | Required; bounded artifact inventory and `ProbeReport` | `foundation` |
| `locate_inputs()` | Required; explicit `InputParserKind` and selected `InputSpec` | `foundation` |
| `parse_status()` | `STATUS_PARSE`; observations, relationships, source records, diagnostics | `foundation` |
| `parse_ctf()` | `CTF_PARSE`; core decoder messages to events/source records/diagnostics | `foundation` |
| `parse_text_trace()` | `TEXT_TRACE_PARSE`; selected artifact to events/source records/diagnostics | `foundation` |
| `apply()` | `EVENT_REDUCTION`; executor returns validated `ChangeSet` | `revision` |
| `revert()` | `EVENT_REVERSION`; executor returns inverse/unknown `ChangeSet` | `revision` |
| `correlate()` | `CORRELATION`; bounded reader/window and typed correlation output | `revision` |
| `project_relationships()` | `RELATIONSHIP_PROJECTION`; durable pre-consistency materialization | `revision`, `composition` |
| `check_consistency()` | `CONSISTENCY_CHECK`; immutable augmented revision world | `revision`, `composition` |
| `project_topology()` | `TOPOLOGY_PROJECTION`; records, connector claims, diagnostics | `presentation` |
| `project_forwarding()` | `FORWARDING_PROJECTION`; forwarding IR mutations | `forwarding` |
| `resolve_forwarding_step()` | `FORWARDING_TRACE`; node-local packet transition result | `forwarding` |
| `analyze_evidence()` | `EVIDENCE_ANALYSIS`; authorized immutable facts to cited observations | `evidence` |

Parsing is scheduled by ingestion. Ordinary ingestion does not schedule
reducers or correlation. Durable ingestion schedules relationship projection
before consistency; other optional hooks require their configured host caller.
Manifest support alone does not promise an HTTP endpoint. Use
`PluginCapabilityExecutor` for isolated optional-hook acceptance, and
`PlanBoundCapabilityRouter` for retained revision/provider authority.
See [capability scheduling](plugin-contract.md#2-capability-boundary).

## Supporting and extension APIs

| Surface | Contract and boundary | Conformance group |
|---|---|---|
| Discovery and validation | Installed instance entry points, module selector, manifest/schema checks, bounded diagnostics | `foundation` |
| `ArtifactReader`, `TraceDecoder` | Core-owned safe artifact reads/materialization and optional CTF decoding; no arbitrary path access | `foundation` |
| Resource/value/event/source models | Typed `ResourceKey`/`KeyAtom`, canonical identity, `PropertyPatch`, `DomainEvent`, `derive_event_uid`, evidence, `SourceRecordEmission`, copy projection, property disclosure | `foundation`, `revision` |
| `ReadOnlyWorld`, `CorrelationReader` | Exact basis/perspective, bounded state/relationship/event queries and explicit quotas | `revision` |
| Schema presentation | Dashboard/table descriptors, resource icons, source groups/types, lane presets, conditions and perspectives; these are data declarations, not extra hooks | `presentation` |
| `FederationLinkerPlugin` | Separate linker identity, `describe_match_policies()` and `link()` through `FederationLinkExecutor` | `presentation` |
| Packet and route models | Packet identity/layers/transitions, constraints, steering, policy/traversal/cycle and route presentation; core combines node-local results | `forwarding` |
| `PluginRuntimeCapability`, `PluginRuntimeSession` | Compatibility `plugin.runtime.open()` context and session members; ordinary parser plug-ins use core runtime v2 | `runtime` |
| `NormalizedDatasetSource`, `IndexedHistory`, `NormalizedDataPolicy` | Revision scope/load/identity/index, input-specific metadata, route-row and source-record projections | `runtime` |
| `RuntimeTemporalProvider`, `RuntimeTopologyProvider`, `RuntimeRouteProvider` | `for_revision()`, `topology_id` and/or `get()`; core validates provider results and owns web exposure | `runtime` |
| `RuntimeApplicationFactory` | Host application injection contract; not an author-required parser hook | `runtime` |
| Registration, execution plans, composition | Exact provider pins, policy digest, sealed deployment, process/inline execution authority, plan/revision-set routers, sessions | `composition` |
| Private analysis host integration | Evidence authorization, citation binding and producer identity; runner/tool services are separate host APIs | `evidence`, `combined` |

The [runtime guide](plugin-author-guide.md#core-owned-runtime-v2-and-the-compatibility-runtime),
[API contract](api-contract.md), and [private analysis guide](private-ai-analysis.md)
cover the last six rows. A compatibility adapter is an advanced extension;
implementing these protocols is not necessary for a normal status parser.

## Validate combinations

| Scenario | Checks and meaningful assertions |
|---|---|
| Parser to durable revision | `foundation` + `revision` + `combined`: teaching smoke, exact resource/evidence identities, retained source records, relationship materialization before consistency |
| Auxiliary provider composition | `composition` + `revision`: exact pins, roles and policy; stale/ambiguous providers fail; malformed materialization does not publish a partial revision |
| Topology to cross-node route | `presentation` + `forwarding` + `combined`: same revision/member/perspective, endpoint authority, packet transitions and qualified connector matches |
| Query and disclosure | `foundation` + `presentation` + `runtime`: schema fields/conditions, source copy projection, resource/history queries and redaction |
| Private evidence analysis | `evidence` + `composition` + `combined`: authorized facts, exact producer and plan, two-node evidence integration, no citations outside input evidence |

The `combined` group includes the executable quickstart, durable review,
workbench, cross-node disagreement, generated-assembly APIs, and control-plane
private-evidence integration. For a new combination, add a small synthetic
scenario asserting intermediate identities and outputs; a successful hook
call or HTTP 200 alone is insufficient.

## Whole-repository checks

The plug-in groups complement the full CI suites; they do not replace them:
full core discovery includes their test modules. When it has already passed
for the same code, use `--list` to verify the inventory and run only additional
new scenarios instead of repeating `--all` or overlapping groups.

```text
python scripts/check_plugin_conformance.py --list
python -m unittest discover -s tests -v
python -m unittest discover -s demo/tests -v
python -m unittest discover -s state-dump-generator/tests -v
npm --prefix frontend run check
python scripts/export_type_stubs.py --check
python -m mypy --python-version 3.12 --strict --no-incremental tests/typing/public_api.py state-dump-generator/tests/typing/generator_public_api.py
python -m mypy --python-version 3.12 --strict --no-incremental src/router_dump_analyzer demo/rsl_demo_plugin demo/rsl_demo_generator state-dump-generator/src/state_dump_generator
python -m mypy --python-version 3.12 --ignore-missing-imports --check-untyped-defs --no-incremental src/router_dump_analyzer/canonical.py src/router_dump_analyzer/route_trace_core.py src/router_dump_analyzer/topology_core.py
python -m compileall -q src demo/rsl_demo_plugin demo/rsl_demo_generator tests demo/tests state-dump-generator/src state-dump-generator/tests
python -m ruff check --select E9,F63,F7,F82 src demo state-dump-generator/src tests state-dump-generator/tests
```

See [CI](../.github/workflows/ci.yml) for supported OS, minimum-Uvicorn,
distribution-install and launcher checks. After modifications, complete
`AGENTS.md`'s documentation drift check and run changed documented smoke paths.
