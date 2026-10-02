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

## Loading and performance boundaries

Measure the changed path with a fixed fixture and interpreter. Distinguish
process-cold and warm provider calls from fixture generation, HTTP transport,
and time to a usable browser view. Use a separate profiler run for attribution;
instrumented seconds are not request latency. The
[topology/route profiler](../scripts/profile_topology_routes.py) and its
[method](topology-route-profile.md) cover direct providers. A small fixture
does not establish full-scale archive performance.

Core owns execution identity, request cancellation, and public loading state.
A compilation cache may retain bounded immutable artifacts derived from exact
source/compiler inputs; it must not retain a trust decision or replace fresh
source reads, live dependency inspection, or before/after invocation checks.
Exercise warm-cache source changes, runtime mutations, and eviction through
the same core callers as cold execution. Use `tests.test_plugin_identity`,
`tests.test_plugin_identity_runtime_imports`, `tests.test_capability_router`,
and `tests.test_provider_execution_boundaries` for these boundaries.

For archive changes, retain traversal of trailing members and rejection of
unsafe names, duplicate members, nonregular entries, size/hash mismatches,
and incorrect projection identity. Validate reordered archives as well as
canonical generator output with `tests.test_demo_assembly_store` and
`tests.test_demo_archive_safety`. Lazy loading may defer work but must not
silently weaken validation or change the accepted data.

For combined browser flows, distinguish core ingestion from durable
materialization and the configured startup runtime. Test slow and failed
secondary requests, cancellation, superseded responses, and partial rendering;
only the current revision/context may publish. Report actual loading stages
without guessed percentages. Browser timeout bounds waiting and does not
prove synchronous backend execution stopped. Run the relevant frontend tests
and browse the resulting integration before claiming UI readiness.

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
