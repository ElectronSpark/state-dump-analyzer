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

Use the installed Python 3.12 environment for both CLI and tests. Setup commands
are in the quickstart. The ordinary status-parser teaching instance is
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
Tie each reported stage to work the adapter actually performs. Use `INDEXING`
while building an index and `READING_ARCHIVE` while processing an archive;
simple fixture reads can retain the core's `LOADING_REVISION` stage. Counting
records alone does not establish that an index was built.

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
