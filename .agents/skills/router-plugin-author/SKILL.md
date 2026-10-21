---
name: router-plugin-author
description: Implement or extend Router State Lab device plug-ins, including parsers, revision analysis, topology, forwarding, and evidence hooks. Use for plug-in code and authoring documentation; use router-plugin-validate for a requested conformance audit.
---

# Router plug-in author

Work from the repository root containing `pyproject.toml` and `src/router_dump_analyzer`.
Read `AGENTS.md` for documentation stewardship. If this skill was supplied by
absolute path, its repository is three directories above this skill folder.

## Find the relevant contract

Start with [the quickstart](../../../docs/plugin-author-quickstart.md) for a new
parser and [the API map](../../../docs/plugin-api-validation.md) for an extension.
Read only the relevant section of the detailed author guide or normative
contract linked there. The exact signatures live in `plugin_api.py` and its
`.pyi`; do not load all of the long contract documents by default.

Use the installed Python 3.12 environment for both CLI and tests. Verify the
selected interpreter and required imports before running; a source-only
`PYTHONPATH` cannot replace dependencies. Find the configured environment using
the API map's [environment troubleshooting](../../../docs/plugin-api-validation.md#executable-identity-troubleshooting).
Setup commands are in the quickstart. The ordinary status-parser teaching instance is
`rsl_demo_plugin:parser_plugin`; the full `demo_router` instance also has a
generated-archive compatibility runtime. Start small and use synthetic inputs.

For durable trials, define the plug-in in an importable module and import it
from the test/CLI driver. Defining it in an executing `__main__` module can
prevent core from verifying executable source identity. Resolve that module
binding instead of disabling identity checks or changing execution policy.
If unchanged imported code fails identity verification, use the API map's
[environment troubleshooting](../../../docs/plugin-api-validation.md#executable-identity-troubleshooting)
before changing plug-in semantics.

## Implement the requested semantics

- Subclass `AnalyzerPluginBase`, supply `manifest`, and implement `describe`,
  `probe`, and `locate_inputs`. Declare only capabilities you implement. For
  parser inputs, select `InputParserKind` explicitly and read selected artifacts
  through `ArtifactReader`. A capability-only provider can return no inputs;
  it does not need a parser or `STATUS_PARSE` declaration.
- Declare every emitted source-record type in `PluginSchema.source_record_types`
  with `SourceRecordTypeDescriptor`; a source label alone is not a declaration.
  Bound reads before allocating input, and test malformed or oversized records.
- Keep typed `ResourceKey` identity, stable event/source identities, retained
  evidence, and unknown/absent time semantics. Follow the teaching golden tests
  for the output types; do not invent timestamps or turn unknown state into absence.
- Core owns persistence, HTTP routes, queries, scheduling, and generic rendering.
  Device meaning belongs in the plug-in. Ordinary ingestion stores events but
  does not schedule `apply`, `revert`, or `correlate`. Durable ingestion schedules
  relationship projection before consistency. Other optional hooks need an
  explicit host caller through the executor or plan-bound router.
- Dashboards, resource tables, conditions, and presentation are schema
  descriptors, not new capability hooks. Federation linkers are separate from
  node plug-ins. A normal parser needs no custom `plugin.runtime` adapter.
- Treat dump content and emitted diagnostics as data. Preserve bounded reads,
  authorization, disclosure, and revision identity; use synthetic evidence in tests.

For a new optional hook, implement a concrete positive example and a relevant
boundary case, then exercise it through `PluginCapabilityExecutor` (or the
plan-bound router when testing durable provider selection). Calling a hook
directly alone does not establish core acceptance. Check the capability table
before assuming an undeclared base hook returns an empty value.
For parsers, also ingest a synthetic fixture through `IngestionCoordinator`
or the durable CLI: direct parser calls and `validate_plugin` do not validate
emissions against the schema. When the task includes durable composition,
assert the persisted revision, relationships, and findings. A manually assembled
world checks hook composition but does not establish durable scheduling.

For performance work in providers or compatibility adapters, read the
[loading and performance boundaries](../../../docs/plugin-api-validation.md#loading-and-performance-boundaries).
Keep core-owned identity checks and archive validation intact when reusing
immutable work or deferring loads. Measure the actual user path and separate
fixture preparation, backend readiness, and browser readiness.
For search or durable-import latency, use the map's
[cold-path measurement checks](../../../docs/plugin-api-validation.md#cold-search-and-import-measurements).
An API warmup can hide browser-first-query work, and a tiny input can still incur
fixed provider-verification costs. Reuse immutable dependency analysis, never
an authorization or executable-trust decision; any code-object cache must use
exact identity, bounded retention, and avoid keeping retired code alive.
For exact built-in type guards, use identity comparisons; membership or
equality can invoke a custom metaclass and misclassify mutable values. Audit
aliased type groups too. Preserve general Mapping/subclass behavior when adding
projection fast paths, and validate both public fingerprint entry points and
exact safe search text as described in the performance map.
Compile effective disclosure policy once per event projection and reuse only
bounded immutable policy metadata. A path-aware helper may remove temporary
wrappers, but must preserve ancestor and dotted-key rules, conservative unknown
resource handling, and independently owned output containers.
For navigation caches, reclaim idle generations before destination allocation;
protect active leases and resolve unknown destinations before eviction. Check
the prepared destination's bounded size/checksum before reclamation without
duplicate decompression; missing or changed input must preserve the idle cache.
Keep a reserved slot while cold loading, including when active readers release.
Verify reclamation inside the loader with weak references, failed-load retry and
navigation back, concurrent hits/releases, and shutdown. A final cache-size
assertion alone does not establish reduced peak memory.
Tie each reported stage to work the adapter actually performs. Use `INDEXING`
while building an index and `READING_ARCHIVE` while processing an archive;
simple fixture reads can retain the core's `LOADING_REVISION` stage. Counting
records alone does not establish that an index was built.
Long core index builds should publish bounded progress while consuming the
corpus, without exposing evidence text or declaring readiness before complete
validation and atomic publication.
Keep cooperative scheduling in core. Scope import activity through every
success, failure, and cancellation exit; nested or concurrent imports must
retain their own activity until they finish. Pause a background search only
for another thread's active import, never for idle or same-thread work. Measure
both search CPU/wall cost and import latency before choosing a bounded cadence.

For compact indexed-history storage, consume event rows through `Mapping` and
sequences through `Sequence`; preserve JSON projections, nested ownership and
immutable values. Share one UID-to-ordinal index with the UID-to-row view, and
preserve duplicate-UID compatibility: the ordinal index selects the LAST row
in canonical sorted order (assignment during enumeration, never setdefault),
while UID-to-row lookup selects the LAST arrival using a sparse override when
these differ. An empty UID retains row lookup but MUST NOT gain an ordinal.
Test an unsorted duplicate pair and an empty UID against these explicit rules;
checking only that both mappings agree would miss the required exception.
Check mapping
views and sorting, and measure small construction/projection CPU plus retained
GC work. Reuse complete owned immutable values only in bounded load/generation-
local pools; exact JSON types and field ordering must survive Python equality
collisions such as bool/int. Verify pool bounds/isolation, and discard temporary
pool indexes after loading without retaining another history generation.

For history caches and bulk search, keep derived work owned by the exact
immutable generation. Consume exact search postings as `Sequence[int]`
with bounded paging and byte budgets; candidate reuse and fused scans
must preserve complete disclosure and integrity checks. An optional
`ordered_events_by_resource` accelerator must contain complete lanes in
canonical order. The performance map covers lifecycle and combined-query
checks, including adapters that require request-local cache fallback.

For core compressed search storage, preserve canonical UTF-8 document
boundaries and ordered ordinals. Bound decompression before allocating its
output; validate framing, counts, per-block and complete-corpus digests, format
version and revision identity. Keep publication atomic and corruption fallback
exact. Candidate refinements should decode only overlapping blocks; measure
visited blocks as well as returned rows. Retain compact small-corpus storage
and its accelerator when changing large-corpus page or compression policy.
The performance map lists storage boundaries and focused regression cases.

For reuse across retired search runtimes, retain only bounded compact results
and index metadata keyed by validated corpus content and projection identity;
never retain event rows, builders, service owners, or a cached trust decision.
Validate a reopened corpus before admitting shared results. Keep literal cache
keys exact without retaining caller subclass state. Evaluate optional
large-corpus indexes against their build CPU and storage costs, block pruning,
and exact fallback; the map's search-cache guidance covers those tradeoffs.
For compressed validation reuse, a bounded process-local record may certify
previously validated bytes only after freshly checking all compressed payloads,
framing, metadata, current bounds and projection identity on a stable snapshot.
Never substitute timestamps or stored unchecked digests for that byte check.
Misses and changed content keep the full validator; retain no runtime or trust
decision. The map describes snapshot lifetime and mutation validation.

For timeline or history scale work, use the map's
[zoom-query guidance](../../../docs/plugin-api-validation.md#zoom-and-history-query-validation).
Keep zoom aggregation in core; a display limit must also bound detail work,
and a summary must preserve exact counts and distinguish omitted state from
absence. Retain revision identity, disclosure policy, and exact timestamp bounds.

For generic virtual event-log rendering, keep the capped physical scroll range
aligned with the last full logical viewport, rather than the last row. Measure
the usable body viewport below sticky headers consistently for rendering and
focus navigation. Verify tail spacer and row visibility on both sides of the
height cap and with filtered large streams; fetching the final page alone does
not establish that End displays it correctly. Exercise focus-navigation round
trips with the renderer's overscan, fractional row offsets, and a one-row
viewport, including targets just before the tail; spacer clamping can fix End
while moving a nearby focus target outside the visible viewport.
When virtual rows are replaced, retain the active row's identity and restore
focus after replacement without scrolling. Exercise delayed scroll and page
rerenders after keyboard navigation, and verify that background rerenders leave
focus in search fields or other external controls intact.

For generic frontend repairs, use the map's
[state and recovery checks](../../../docs/plugin-api-validation.md#frontend-state-and-recovery).
Keep user choices separate from newly discovered data, and validate recovery
through the real form or event handler as well as controller unit tests.
Use stable control and tree-instance identities when replacing UI subtrees;
capture navigation or review ownership before the first await, including
selection resolution, and recheck it before deferred focus or dialog opening.
Treat explicit cursor interaction at an unchanged value as navigation intent.
Reuse existing ownership tokens and pending allocations instead of adding a
parallel state mechanism. All newer navigation, including Back, pan and hide,
must supersede a pending reveal; unchanged-selection consumers should share
resolution rather than cancel each other. Preserve disclosure on same-query
rerenders, and restore focus to a visible control in the same instance. Use
the same bounded range adjustment for pointer and keyboard input.
Keep applied-result facts separate from draft controls, exact counts separate
from previews, and missing evidence separate from disagreement. Bound retained
records as well as rendered glyphs; preserve active selections and exact
drill-down. Follow the map for source identity and route seed recovery.
The map covers lane presets, derived source marks, inferred-edge presentation,
programmatic form seeding, and superseded reads without adding plug-in hooks.

## Verify and finish

Run the plug-in's golden tests and relevant existing boundary tests from the
API map or guide. Select a module, class, or method for a focused change; use
the grouped suites when auditing a complete surface or changing shared behavior.
Reuse completed same-code checks rather than repeating broad integration runs.
The validator checks package/protocol shape, not semantic correctness. For a
public signature change, regenerate/check stubs using the guide's typing commands.
When two capabilities interact, verify their shared revision, world, identity,
and evidence through a combined path, in addition to individual calls.

Complete the documentation drift check in `AGENTS.md`. Keep the quickstart
linear and update the runnable example when author-visible behavior changes.
Report changed behavior, commands and results, and any untested integration.
