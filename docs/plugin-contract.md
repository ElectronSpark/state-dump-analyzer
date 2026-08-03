# Plugin contract and lifecycle

There are three owners:

- **Core** owns trust boundaries and mechanics: safe artifact materialization,
  canonical envelopes and identity, clock transforms, interval reconstruction,
  persistence, budgets, APIs, orchestration, and generic rendering.
- **Node/device plug-ins** own platform-, release-, layer-, and
  protocol-specific meaning: parsing, typed keys, status normalization,
  mutations, local correlations, forwarding/topology projections, and
  declarative presentation.
- **Federation/linker plug-ins** own cross-node inference over bounded normalized
  claims: peer/domain matching, corroboration, ambiguity policy, and inter-node
  link semantics. They cannot read raw node artifacts or replace node-local
  state.

Core code never branches on plug-in kind, relation, source-type, source-group,
or key-field names. The migration audit is recorded in
`docs/core-plugin-boundary-audit-2026-07-22.md`.

The executable reference types are in
`src/router_dump_analyzer/plugin_api.py`.

If this is your first plug-in, start with
`docs/plugin-author-quickstart.md` and the runnable
`demo/rsl_demo_plugin/__init__.py` teaching slice. This document is
the normative reference, not the recommended reading order for a first
implementation.

## 1. Packaging and discovery

Each plugin is an independently versioned Python distribution with an entry
point. A minimal declaration looks like:

```toml
[project.entry-points."router_dump_analyzer.plugins"]
synthetic_router_2025 = "vendor_router_plugin:plugin"
```

The entry-point target is a module-level plug-in **instance**, not a class or
factory. The loaded object implements `AnalyzerPlugin` and exposes a
`PluginManifest`. New implementations should subclass `AnalyzerPluginBase`;
it supplies safe empty behavior for undeclared optional capabilities and fails
loudly when a declared capability's hook was not overridden.

Install a candidate distribution in the analyzer environment, run
`router-dump-plugin-validate` against a representative plug-in-owned synthetic
artifact, and run that distribution's golden tests. The exact known-good
copy-paste workflow is maintained in
[Plug-in author quickstart, step 1](plugin-author-quickstart.md#1-run-the-known-good-example).

A device plug-in depends on `router-dump-analyzer-core`, never on the demo
package. Core owns the generic browser pages and interaction code; plug-ins
contribute validated declarative presentation descriptors and never ship executable frontend code.
Precomputed offline fixtures and their materializers are application-specific
extensions, not standard `AnalyzerPlugin` hooks and not shortcuts around the
ordinary capability hooks for a live parser. The bundled example uses the
illustrative provider ID `demo.example-router`; its current offline projection
and evidence format is documented only in the
[demo guide](../demo/README.md#generated-mock-dumps).

The validator checks entry-point construction, manifest/core compatibility,
schema determinism, required hooks, capability overrides, empty-inventory
robustness, and the representative inventory's explicit parser dispatch. It
does not open the supplied artifact or run the parser. Product conformance still
requires a plug-in-owned synthetic corpus and the tests in section 8.

The server records distribution name/version/hash, manifest, plugin API version,
configuration hash, and decoder version in the analysis revision.

Do not use filename-based module discovery or import Python files found in the
dump. The deployment owns an allowlist of installed plugin distributions.

The executable v1 protocol does not inject runtime configuration into a plug-in.
Do not invent a hidden environment-variable or global configuration channel.
Package immutable defaults with the plug-in; any future configurable constructor
or configuration object requires a versioned protocol addition. The
`supported_software_versions` string is recorded for humans and reproducibility;
the plug-in's `probe()` owns version interpretation and returns `match_kind`.

### Core-owned ingestion runtime and compatibility sessions

The standard `AnalyzerPlugin` parsing contract is the normal executable path.
An ordinary parser plug-in does not expose a `runtime` attribute. When selected
by the core `router-dump-analyzer` web command, core wraps its standard hooks in
`CoreIngestionRuntime`, whose capability ID is
`router_dump_analyzer.runtime.v2`.

The core accepts exactly one of these selectors:

```text
router-dump-analyzer --plugin ENTRY_POINT_NAME --input PATH
router-dump-analyzer --plugin-module PACKAGE[.MODULE][:ATTRIBUTE] --input PATH
```

The analysis application's OpenAPI JSON, Swagger UI, and ReDoc routes are
disabled by default. The core CLI accepts an explicit `--expose-api-docs` only
on a loopback bind; a plug-in cannot enable those routes or weaken that host
policy.

`--plugin` resolves exactly one installed
`router_dump_analyzer.plugins` entry point. `--plugin-module` is a
source/development path that imports the named module; `ATTRIBUTE` defaults to
`plugin`. Both selectors must resolve to a module-level instance, not a class or
factory. Core validates `PATH`, inventories a regular file, directory, tar, or
ZIP, and owns the artifact-reader lifetime. It then:

1. calls deterministic `describe()`;
2. calls `probe()` with safe inventory metadata;
3. calls `locate_inputs()` and validates each selected logical artifact;
4. dispatches `STATUS`, `TEXT_TRACE`, or `CTF` only when the corresponding
   manifest capability and parser hook agree;
5. validates every discovery/parser output and evidence reference;
6. assigns canonical resource/source/revision identity; and
7. publishes the normalized node dataset through the core application.

The plug-in receives logical artifact UUIDs, portable logical names, read-only
streams, and session-private materializations only. It never receives `PATH`,
an archive extraction destination, or a host-global path. A private
materialization becomes invalid when the reader session closes.

The current core-built v2 session supplies `revision_store`, `data_source`, and
`data_policy` for the normalized workspace. Its optional
`temporal_provider`, `topology_provider`, and `route_provider` are all `None`;
its history source currently has no optional structural index. Those APIs
remain unavailable until an executable provider contract supplies them. Core
does not infer a provider from resource names or plug-in properties.

`plugin.runtime` and `router_dump_analyzer.runtime.v1` remain a compatibility
path only for independently versioned precomputed fixtures/assemblies, such as
the bundled 100K-per-node demo. A new live parser must use the standard hooks
above rather than adding its own path-opening adapter. When this compatibility
surface is present, it is not a `PluginCapability` enum value and does not
change parser dispatch.

The compatibility runtime contract is:

- `capability_id` equals `router_dump_analyzer.runtime.v1`;
- `open(input_path: Path)` returns a context manager; and
- entering that context yields one `PluginRuntimeSession` with no HTTP, ASGI,
  or browser objects.

The session has six structural surfaces:

| Member | Normative requirement |
|---|---|
| `revision_store` | Required `RevisionStore` implementation for immutable assembly and revision access. |
| `data_source` | Required `NormalizedDatasetSource` for revision-scoped normalized dataset loading and an optional structural history index. |
| `data_policy` | Required `NormalizedDataPolicy` for opaque analysis/workspace metadata, plug-in route rows, and safe retained-source formatting. |
| `temporal_provider` | `RuntimeTemporalProvider` or `None`; a supported provider returns core `TemporalTopologyService` from `for_revision()`. |
| `topology_provider` | `RuntimeTopologyProvider` or `None`; a supported provider exposes `topology_id` and returns core `MultiNodeTopologyService` from `get()`. |
| `route_provider` | `RuntimeRouteProvider` or `None`; a supported provider returns core `MultiNodeRouteService` from `get()`. |

Core validates a compatibility session before serving, enters it for the FastAPI
application lifespan, binds it request-locally, and closes the context once at
shutdown. Core constructs `NormalizedDataService`; the plug-in must not
implement generic state, relationship, resource-table, dashboard, range,
redaction, search, or client-projection algorithms. The plug-in owns
input-format interpretation, normalized data, and device/protocol policy. Core
owns the executable, application factory, lifespan, middleware, every HTTP
route, error mapping, generic services,
frontend host, page templates, assets, and interactions.

`NormalizedDatasetSource` has exactly four operations:

- `revision_scope(revision_id)` returns a context manager;
- `load_dataset(revision_id=None, **selection)` returns one normalized
  dataset;
- `revision_id(dataset)` returns its exact stable revision identity; and
- `indexed_history(dataset)` returns a structural `IndexedHistory` or `None`.

`NormalizedDataPolicy` has exactly five operations:

- `analysis_metadata(dataset)` returns opaque plug-in analysis metadata;
- `workspace_metadata(dataset, *, revision_id, history_mode)` returns the
  generic workspace envelope values;
- `route_resolution_capability(dataset)` returns the node route catalog, or
  `{"available": false, "routes": []}`;
- `route_row(route_id, dataset)` returns an exact declared row or raises
  `KeyError`; and
- `source_record_for_event(event)` returns the plug-in-safe retained source
  record representation.

The optional indexed history may accelerate the same normalized semantics; it
must not change resource identity, temporal validity, redaction, or query
results.

A compatibility runtime must not return or register FastAPI, `APIRouter`,
middleware, routes, templates, HTML, JavaScript, or CSS. A standard parser
without runtime v1 is served through core-owned runtime v2. The installable
precomputed-fixture example in `demo/rsl_demo_plugin/session.py` and its tests
exercise the compatibility boundary.

### Durable admission, sessions, and review remain core-owned

The optional `router-dump-ingest` command, API-only `router-dump-server`, and
`/v1/control-plane` queue invoke the same standard `AnalyzerPlugin` hooks. They
do not define another plug-in kind or optional capability. A deployment
constructs an explicit
`PluginRegistry` from installed entry points or explicitly named development
modules. Uploaded data cannot install code, extend that registry, or choose a
plug-in outside it.

For each admitted artifact, core:

1. streams and hashes the bytes under its upload limit;
2. persists the upload/import plus the complete fixture-admission request and
   operation ID in an explicit tenant/project/workspace scope, then records
   the catalog result idempotently;
3. safely inventories the admitted artifact for every allowlisted
   deterministic `probe()`;
4. records the sorted candidate set and its `probe_set_hash`;
5. either applies the configured exact selection policy or waits for a client
   to echo the probe-set hash and exact plug-in ID/version/package identity,
   then stores that selection's scope-bound idempotent request/response
   receipt;
6. runs ordinary input discovery and parser dispatch under a leased queue
   claim; and
7. durably stages the validated canonical dataset plus an exact publication
   operation; and
8. publishes that operation idempotently as a new immutable catalog revision.

A lost fixture-admission response replays the exact staged operation without
creating a second fixture. A retry before publication is staged may invoke the
same plug-in again. Publication-only recovery replays the staged catalog
operation without invoking the plug-in. Therefore `describe()`, `probe()`,
`locate_inputs()`, parsing, IDs, and normalized output MUST remain
deterministic for the same bytes and immutable package/configuration. Plug-ins
MUST NOT use wall-clock time, randomness, mutable global state, tenant
metadata, or queue attempt number to change semantics.

Admission and publication catalog calls have a separate core deadline after
plug-in output is staged. Production mode enforces it in a disposable spawned
process; the built-in catalog reopens its durable database there and also
bounds lock/database waits through commit. An external deployment publisher
must be spawn-picklable or reconstruct its client during unpickling and should
apply the supplied remaining budget to RPC work. An ambiguous expiry preserves
the exact outbox and artifact pin. It MUST NOT cause the parser to run again
during publication-only recovery and does not add any plug-in timeout hook.

Plug-ins do not receive tenant, project, workspace, session, principal,
idempotency key, lease, annotation, or HTTP response objects. They do not open
the upload/catalog/review SQLite databases or content store. Multi-revision
sessions, immutable session snapshots, review annotations, manual
correlations, soft deletion, audit rows, and deterministic report rendering
are generic core mechanics over already validated revision-qualified
identities.
The core assigns the report-only `CorrelationReportProvenanceClass` values;
plug-ins continue to use `Provenance` only for normalized facts and never label
their own report section as user assertion or core corroboration.
At the AI-facing report boundary, core recursively converts Unicode `Cc`,
`Cn`, `Cs`, `Zl`, and `Zp` characters, every `Cf` character except U+200C ZWNJ
and U+200D ZWJ, every `Zs` separator except ordinary ASCII space, and U+115F,
U+1160, U+17B4, U+17B5, U+2800, U+3164, U+FFA0, U+13441, and U+13442 in
plug-in strings and object keys to visible `\\uNNNN` or
supplementary `\\UNNNNNNNN` text. Core doubles caller-supplied backslashes
before conversion, so literal escape-looking values and keys remain distinct
from actual unsafe characters in canonical JSON and its digest. This property
rule covers the complete Unicode TAG block and future unassigned invisible
code points. U+16FE4 KHITAN SMALL SCRIPT FILLER
remains valid as a legitimate cluster-layout control inside visibly anchored
text. Combining grapheme joiner, unregistered or misplaced variation
selectors, U+FFFC OBJECT REPLACEMENT CHARACTER, and private-use (`Co`) text
may remain in a bounded source display label, but core makes each such
character explicit in the AI-facing projection while preserving surrounding
visible text. U+FE0E/U+FE0F remain raw only when the exact adjacent
base-selector pair is registered in the vendored Unicode 15 emoji-variation
table. Each pair inside a ZWJ sequence is evaluated independently;
standalone, repeated-on-one-base, and unregistered selectors are escaped.
Every selector remains rejected in identifiers.
Plug-ins MUST NOT encode meaning only through invisible or private-use glyphs.

The only durable-admission context exposed through `ArtifactInventory` is an
optional caller-supplied node hint and bounded JSON import metadata. The
headless command names these `--node-hint` and `--metadata-json`; HTTP names
them `X-Node-Hint` and `X-Import-Metadata`. Probe and parsing receive the same
values. Core does not mix tenant/project/workspace, fixture/import, principal,
queue, or authorization coordinates into that metadata.

Cross-node exact matching follows the same division. A node or federation
plug-in declares a bounded matcher identity, type-preserving opaque key,
evidence, and payload meaning. Core's `exact_match_claims()` groups only exact
keys and emits bounded cross-partition candidates with
matched/ambiguous/unmatched state; it accepts at most 100,000 claims by
default and materializes at most 1,000 candidate pairs unless the caller sets
smaller or explicitly bounded limits. The exact non-configurable ceilings are
100,000 input claims and 100,000 materialized candidates; both
`max_claims` and `max_candidates` may be set from zero through that ceiling,
and a larger request fails before grouping/materialization. Retained claim
payload, evidence, and provenance must be bounded JSON-safe values. Core's
`corroborate_events()` emits
independent facts only from explicit causal links, exact shared source-record
or resource identity, and uncertain time ordering. Core MUST NOT infer a match
from labels, similar strings, close timestamps, or vendor payload fields, and
the caller—not the utility—owns policy aggregation.

Generic evidence and provenance supplied to `ExactMatchClaim`,
`ExplicitCausalLink`, `ResolvedEventRef`, or `CorroborationFact` are value
snapshots, not shared object references. Core validates and recursively
detaches their bounded JSON containers at construction and snapshots resolved
events again when `corroborate_events()` begins. Plug-ins must compare values,
not Python object identity, and must not expect a later mutation of a supplied
dictionary or list to rewrite a match result or hashed report.

Plug-ins may import the complete reusable construction/result vocabulary from
`router_dump_analyzer`: `MatcherId`, `ExactMatchClaim`,
`ExactMatchCandidate`, `ExactMatchGroup`, `ExactMatchResult`,
`ExactMatchState`, `EventIdentity`, `SourceRecordIdentity`,
`ExplicitCausalLink`, `ResolvedEventRef`, `CorroborationFact`,
`CorroborationOutcome`, `CorroborationReasonCode`, `TemporalRelation`, and
`CorroborationError`, plus both functions. Do not reach into
`router_dump_analyzer.corroboration` for these public types.

The implemented local store/queue is transactional and restart-recoverable.
Its durable `ControlPlane`, API-only server, and headless command execute
plug-in probe and ingestion in deadline-bounded, killable spawned children.
`router-dump-server` fixes its repeatable installed-entry-point or direct-module
allowlist at construction, requires a host-owned identity resolver (or the
loopback trusted-header development adapter), and mounts no plug-in-owned
routes, analysis runtime, frontend, or assets. This is fault
isolation, not a plug-in sandbox, distributed queue, authentication layer,
authorization service, or TLS endpoint. Exact operator routes and limits are
documented in
[`control-plane.md`](control-plane.md); none is an extension point for a
plug-in.

## 2. Capability boundary

| Capability | Plugin responsibility | Core responsibility |
|---|---|---|
| Probe | Detect platform/version from safe inventory metadata and return a structured probe report. | Run every allowed probe with limits and resolve ambiguity explicitly. |
| Locate | Select logical artifacts/parser roles or emit structured missing-input diagnostics. | Materialize only those artifacts into a private workspace. |
| Status parse | Yield resource and relationship observations, scoped completeness markers, retained `SourceRecordEmission` values, and precise evidence locators. | Batch validation, source-record identity assignment, storage, diagnostics. |
| Trace parse | Map dependency-free core CTF records or raw text into domain events and retained `SourceRecordEmission` values. | When configured, own the `TraceDecoder`, normalize native messages, retain raw time/source order, enforce quotas, and persist decoder diagnostics. The current runtime ships no built-in CTF decoder. |
| Source-record presentation | Declare source-group metadata, source-type labels/colors/group membership, and optional regex-lane presets; link decoded records to domain events when normalization succeeds. | Validate group/type references, retain matched and unmatched timestamped records, assign stable IDs, validate regexes, page/query records, and implement generic timeline/log navigation. |
| Reduce | Convert one event into all direct/derived state and edge changes. | Deterministic ordering, interval materialization, checkpointing. |
| Revert | Invert an event when information permits. | Mark non-invertible state unknown and measure reconstruction coverage. |
| Correlate | Query a bounded indexed reader and emit cross-layer edges, event causal links, and clock anchors. | Clamp windows/budgets, persist evidence/quality, and reject invalid references. |
| Check | Return PASS/FAIL/UNKNOWN findings. | Execute rules at selected time/revision and aggregate dashboard results. |
| Forwarding | Project bootstrap or bounded `ChangeSet` deltas into a negotiated typed forwarding IR. | Validate/version/store deltas; own LPM, recursive resolution, cycle/limit handling, and explanation API. |
| Topology/status projection | Declare independently selectable status perspectives and named topology projections; materialize plugin-defined topology resources, relationships, and usability state. | Resolve temporal bases, validate projection/perspective combinations, query stored intervals, preserve unknowns, and expose bounded state/topology APIs. |
| Cross-node federation | Match bounded normalized claims, preserve candidates, and emit matched, ambiguous, unresolved, or conflicting inter-node semantics. | Freeze each member basis, invoke the selected linker with budgets, validate/store its output, and never guess a non-exact match. |

### Hook selection and input dispatch

Every node/device plug-in implements `describe()`, `probe()`, and
`locate_inputs()`. Optional behavior is advertised with the standard
`PluginCapability` values:

| Capability | Hook |
|---|---|
| `STATUS_PARSE` | `parse_status()` |
| `CTF_PARSE` | `parse_ctf()` |
| `TEXT_TRACE_PARSE` | `parse_text_trace()` |
| `EVENT_REDUCTION` | `apply()` |
| `EVENT_REVERSION` | `revert()` |
| `CORRELATION` | `correlate()` |
| `CONSISTENCY_CHECK` | `check_consistency()` |
| `TOPOLOGY_PROJECTION` | `project_topology()` |
| `FORWARDING_PROJECTION` | `project_forwarding()` |
| `FORWARDING_TRACE` | `resolve_forwarding_step()` |

`PLUGIN_CAPABILITY_HOOKS` is the executable mapping used by validation. New
plug-ins use the enum values rather than copying arbitrary capability strings.
Custom opaque strings are retained only as compatibility extensions and do not
activate core behavior.

### Core caller for optional capabilities

Core services and adapter code MUST call optional semantic hooks through the
root-exported `PluginCapabilityExecutor`; they MUST NOT invoke those hooks
directly. The constructor takes the plug-in, an optional already-validated
`PluginSchema`, and optional core-owned `PluginCapabilityLimits`. It calls
`describe()` itself when no schema is supplied.

| Executor call | Validated result |
|---|---|
| `apply(event, world)` | `ChangeSet` |
| `revert(event, world_after)` | `ChangeSet` |
| `correlate(reader, window)` | `CorrelationExecutionResult` |
| `check_consistency(world)` | `ConsistencyExecutionResult` |
| `project_topology(request, world)` | `TopologyExecutionResult` |
| `project_forwarding(request, world)` | `ForwardingProjectionExecutionResult` |
| `resolve_forwarding_step(request, world)` | `ForwardingStepExecutionResult` |

Before invocation, the executor requires the corresponding standard manifest
capability and callable hook. For world-reading hooks it supplies a bounded
read-only facade that charges `state_of()`, `iter_states()`, `related()`, and
`iter_relationships()` results against one budget and closes iterators.
`correlate()` instead receives the caller-supplied bounded/indexed
`CorrelationReader`; the executor validates the exact `CorrelationWindow` and
the returned stream. It closes every plug-in output iterator.

All requests, outputs, resource keys, property roots, relationships, causal
types, status perspectives, topology projection/perspective pairs, forwarding
IR versions, references, evidence, and diagnostic envelopes are validated
against the immutable schema and manifest. The default executor ceilings are
50,000 world reads, 50,000 change items, 50,000 correlation outputs, 10,000
consistency outputs, 100,000 topology outputs, 100,000 forwarding outputs,
1,000 diagnostics, 64 evidence items per output, and 4,096 resource references.
A request's smaller limit still applies; a plug-in cannot enlarge these
core-owned ceilings.

Recoverable `PluginDiagnostic` values remain in the typed execution result.
Any non-recoverable diagnostic raises `PluginCapabilityExecutionError` with
the diagnostics attached. An undeclared capability raises
`PluginCapabilityUnavailableError`; a malformed caller request raises
`PluginCapabilityInputError`; a malformed, invalid, or over-limit result raises
`PluginCapabilityOutputError`. Plug-in exceptions are wrapped in this
execution-error boundary rather than escaping as a partially valid result.

Caller validation MUST finish before the optional hook is resolved or invoked.
The three error domains are caller input, hook execution, and plug-in output;
implementations MUST NOT label a caller-owned request defect as a plug-in
execution or output failure.

This executable caller makes optional hooks directly testable and reusable; it
does not itself publish a temporal, topology, or route provider. The current
core-owned runtime-v2 session still leaves those providers `None` and exposes
no route catalog.

Every new `InputSpec` sets `parser_kind` explicitly:

| `InputParserKind` | Core dispatch |
|---|---|
| `STATUS` | `parse_status(reader, spec)` |
| `CTF` | `parse_ctf(spec, messages)` |
| `TEXT_TRACE` | `parse_text_trace(reader, spec)` |

`role` and `parser_id` remain opaque plug-in vocabulary; the core never parses
them to choose a hook. `parser_kind=None` is a legacy compatibility shape and
fails the default author validator.

Plugins never receive application database credentials and never mutate core
tables. They return records through a validated IPC/batch channel.

`InputSpec.artifact_ids` may name several files that form one logical input. This
is required for CTF, where `metadata`, data streams, and optional index files must
be handed to Babeltrace as one private directory tree. A single materialized file
path is not a sufficient CTF contract.

`CoreArtifactReader` accepts one regular file, directory, tar, or ZIP and
rejects symbolic-link/junction components, non-regular archive members, unsafe
or non-portable names, duplicate/case-fold-colliding names, and quota
violations. Its default limits are 10,000 artifacts, 32 path components, 512
MiB per artifact, 2 GiB total expanded bytes, and a 1,000:1 compression ratio.
Durable candidate probing and the later parser run use the same
`ArtifactLimits` instance from the registered `IngestionCoordinator`; selection
never substitutes a looser reader default.
The plug-in receives opaque logical artifact UUIDs and portable names through
`DumpInventory`; `open_binary()` returns a new read-only stream, while
`materialize_private_path()` and `materialize_private_tree()` return
session-private copies. None exposes the original host path. All access fails
after the reader closes.

Every runtime-v2 discovery/parser result is validated before normalization.
The current default ceilings are 10,000 `locate_inputs()` outputs and 2,000,000
parser outputs. Across one ingestion, the aggregate defaults are 2,000,000
plug-in/decoder outputs, 2,000,000 decoder outputs, 100,000 diagnostics,
4,000,000 evidence items, 4,000,000 subject references, 4,000,000
source-to-event links, 64,000,000 normalized value units, and 256 MiB of UTF-8
text. One output may contain at most 4,096 evidence items, 4,096 event subjects,
and 4,096 source-to-event links. One output value is separately bounded to 16
nested levels, 1,024 items in one container, 4,096 total value units, 65,536
units for one string/byte atom, and 4,096 bits for one integer. The validator
rejects booleans masquerading as integers, non-finite floats, reference cycles,
unsupported value types, undeclared schema references, invalid observation
bounds, evidence outside the selected input, wrong output classes, and
non-recoverable diagnostics. It does not coerce, truncate, stringify, or partly
publish an invalid output.

Every core-declared temporal nanosecond coordinate is an exact signed `int64`
(`-2^63` through `2^63-1`), or `None` only where its type explicitly permits
unknown time. This includes source, evidence, and CTF timestamps; mutation,
observation, and validity bounds; `AbsoluteTimeSelector.time_ns`;
`RelativeToWatermarkSelector.offset_ns`; reconstruction watermark and resolved
basis bounds; topology and connector validity; and capability outputs.
Uncertainty values and paired bounds must remain valid inside that same range.

`DomainEvent.timestamp_uncertainty_ns` is either absent or an exact integer
from zero through `2^63-1`, and uncertainty cannot exist without a timestamp.
The complete `timestamp_ns ± timestamp_uncertainty_ns` interval must also fit
signed `int64`. Public constructors enforce their local contract for authors,
and the ingestion host revalidates the complete nested output so a forged or
subsequently mutated dataclass cannot poison a durable revision and fail only
when a report is read.

When a deployment supplies a core `TraceDecoder`, the coordinator consumes its
decoder diagnostics and
passes the plugin only an `Iterable[CtfMessage]`. That union represents event,
stream/packet/activity boundary, discarded-event, and discarded-packet messages
with stable ordinals, trace/stream identity, clocks, normalized payload/context,
and evidence. A native `bt2` object or iterator is never plugin input. CTF roles
use `parse_ctf(spec, messages)`; text-log roles use the separate
`parse_text_trace(reader, spec)` hook and only the quota-enforced reader.
The current core-owned runtime-v2 constructor does not install a decoder;
selecting a CTF `InputSpec` without one fails closed with
`CTF input requires a core TraceDecoder`.
Mapped `DomainEvent` records retain the core `SourceRecordRef` (source, trace,
stream, packet, and message ordinal); a plugin must not hide source identity only
inside a human locator.

The core may retain any timestamped decoder input as a generic `SourceRecord`,
including CTF messages, syslog lines, agent callbacks, and records decoded from
status text. Parser hooks yield `SourceRecordEmission` with the plug-in-owned
`source_type`, decoded record name/message, attributes, evidence, and optional
`matched_event_uid` or plural `matched_event_uids`. The emission deliberately
has no `source_record_uid`: the core validates it, assigns stable identity, and
persists the resulting `SourceRecord`. No match is also a first-class result:
unmatched records remain queryable and can appear on dedicated timeline lanes.
The core owns stable source-record IDs, timestamp normalization, storage,
pagination, range membership, and source-to-domain links.

`SourceRecordEmission.copy_text` is an optional plug-in-materialized safe
plain-text export of that source item. It is separate from the bounded
human-readable `message`. The plug-in must redact it before emission because
the core treats the content as opaque and exports it verbatim. It must be a
string, contain no NUL, and contain at most 65,536 UTF-8 bytes. The core must
not execute a plug-in formatter in the browser, infer text from a source type,
or ship `copy_text` in ordinary virtual log, timeline, search, or bootstrap
pages. An explicit selection projection validates the string, orders and
deduplicates linked source records, and applies a maximum of 5,000 fragments
and 1 MiB aggregate UTF-8 text. The hosting service authorizes that projection;
the browser performs the Clipboard API write. Absence means that record is not
copyable.

`SourceRecordGroupDescriptor.copy_action_label` is optional presentation
vocabulary of 1 to 80 characters. It may be used only when the copyable
fragments resolve to one declared group. A selection spanning groups uses a
core-owned generic label.

`PluginSchema.source_record_types` contains labels, descriptions, and safe
colors. `PluginSchema.record_lane_presets` may provide useful source filters,
such as unmatched CTF records or Ethernet Segment messages. These presets are
declarative regex/source-type filters only. The browser may add or remove custom
rules, but the core applies the same pattern-length, feature, lane-count,
haystack, and result-size limits to plug-in presets and user-created rules.
Plug-ins never provide executable browser matching code.

The supported record-pattern grammar is intentionally smaller than Python
regular expressions: each top-level alternative consists of literals,
character classes, dot, start/end anchors, and no more than one `*`, `+`, or
`?` quantified atom. Groups, counted repetition, lookaround, backreferences,
unsupported escapes, empty alternatives, and ambiguous or nested repetition
are invalid. Presets are validated when the schema is built and again through
the same runtime compiler used for request-authored lanes; there is no
backtracking-regex fallback.

## 3. Required semantics

### Resource keys

- Keys are typed and ordered, not colon-joined display strings.
- `ResourceKey.parts` is a non-empty tuple of at most 32 unique named parts.
  Part names and values are bounded; nested tuples have bounded depth and
  cardinality, integers have a bit-length ceiling, and text/bytes have a length
  ceiling.
- Values are limited to `int`, `str`, `bytes`, `UUID`, `KeyAtom`, and nested
  tuples of those types. Floats, lists, mappings, and arbitrary objects are
  invalid rather than coerced.
- Boolean key parts are forbidden because Python otherwise conflates `True` and
  integer `1`; encode such a discriminator as an explicitly tagged string/int.
- The same logical key after a confirmed delete/recreate may be a new incarnation.
- Unknown references are emitted as keys and become placeholders; they are not dropped.
- Canonicalization rules are part of the plugin's compatibility contract.

Analysis `revision_id` values are core-owned opaque identifiers, not resource
keys or plug-in vocabulary. They may contain `/`. A plug-in must preserve them
unchanged and must not parse them for node, platform, or resource semantics.
Clients must percent-encode the complete value in a revision-scoped URL; the
server uses a path-aware revision parameter so lookup receives the decoded ID
unchanged.

### Evidence

Every semantic output includes evidence where evidence exists: observations,
events, mutations, relationship changes, causal links, clock anchors, findings,
and forwarding mutations. A source item includes an artifact ID and locator such
as:

- `line:120-137`
- `bytes:1048576+320`
- `ctf:stream=2,message=481`
- `json-pointer:/updates/12`

The locator must be stable within the immutable artifact and sufficient for the
source-context endpoint. Include raw clock data even when normalized time exists.

### Updates and unknowns

- `apply()` receives the world immediately before the event, and the returned
  `ChangeSet` is atomic. A plugin may therefore create a parent, required child
  resources, and their relationships without exposing an invalid intermediate
  world.
- The core derives the user-facing effect `created`, `modified`, `deleted`,
  `unchanged`, or `unknown` from the mutation and that pre-event world. `UPSERT`
  against an existing resource is a modification even when the vendor callback
  called it `add` or `create`.
- Event outcome and state effect are independent. A failed event may return an
  empty `ChangeSet` (the normal no-side-effect case), a partial change, or an
  unknown change according to plugin semantics. The core never changes state
  merely because an outcome is non-OK.
- A partial update changes only named fields.
- Null, absent, deleted, and unknown are distinct.
- `before=None` means the prior value is not supplied, not that it was null.
- Callback outcome is separate from the mutation result and observed final state.
- `revert()` returns one `ChangeSet` that may combine known inverse mutations and
  field/edge-level `UnknownChange` records. One unknowable field must not discard
  the event's other provable inverses.
- `PropertyPatch.set_values`, `remove_fields`, and `unknown_fields` are pairwise
  disjoint. A `None` value in `set_values` is explicit null; removal is known
  absence; an `UnknownField` is an evidence gap. When `complete=false`, omitted
  fields remain untouched.
- `field_quality` and before/after unknowns preserve property-level quality
  instead of assigning one blanket truth value to a state.

### Capture anchors

Every resource and relationship observation carries its individual capture-time
interval. A status parser must not copy a dump manifest timestamp onto every
record unless the capture mechanism proves they were simultaneous. A
`RelationshipCollectionObservation` declares completeness only for its exact
owner, direction, relation type, and capture interval; omission outside that
scope proves nothing. The core stores observations separately from mutations and
uses them as reconstruction constraints, never as a fabricated global snapshot.
The current runtime-v2 ingestion slice validates and retains these markers as
private normalized ingestion metadata, but does not yet materialize them into
public relationship intervals or completeness query semantics.

A node plug-in declares raw clock domains and emits anchors with the
device-specific evidence needed to interpret them. It does not fit a hidden
global offset, align nodes, or resolve an API selector. The core validates
anchors, fits/version-controls transform segments, propagates uncertainty, and
resolves every selected member independently. A federation/linker plug-in
receives those frozen per-member bases and must preserve them.

Absolute and relative external queries use core-owned temporal selector types:

- `AbsoluteTimeSelector(time_ns, clock_domain, clock_policy)` asks the core to
  map one absolute instant into each selected node's local clock domain.
- `RelativeToWatermarkSelector(offset_ns, scope, clock_policy)` uses a zero or
  negative offset from the latest complete `ReconstructionWatermark` for the
  exact `WatermarkScope(node_id, status_perspective_id,
  topology_projection_id)`.

Both selector coordinates use the signed-`int64` rule above. Relative selector
resolution also performs checked arithmetic: if `watermark + offset_ns` would
leave the signed-64 range, the query fails closed instead of wrapping or
silently changing the requested instant.

A watermark is not the greatest event timestamp. It means reconstruction is
complete through that point for exactly the named node, status perspective, and
optional topology projection. A control-plane watermark cannot anchor a
hardware-perspective query, and an unrelated late log record cannot advance any
status watermark. The core returns each node's `ResolvedNodeBasis`, including
local and absolute uncertainty ranges, mapping method, evidence, quality, or an
explicit reason such as `clock_unaligned`.

The watermark's local time and clock domain are sufficient for a relative
query. Absolute bounds are optional mapping metadata: a node with no wall-clock
transform can still reconstruct `-5s` from its own exact scoped watermark. Only
an absolute selector requires a registered transform from its named source
clock domain.

For the runtime topology envelope, watermarks are indexed first by
`status_perspective_id` and then by `projection_id`. Each declaration carries
`local_time_ns`, `clock_domain`, and `complete`, plus optional
`query_time_ns`, `mapping_method`, quality, and an
`absolute_min_ns`/`absolute_max_ns` pair. Supplying only one absolute bound is
invalid, and `complete: false` cannot anchor a query. The coordinator qualifies
the declaration with node/member, revision, plug-in set, plug-in run,
projection, and perspective in the returned `watermark_scope`. It reports
`watermark_source: projection_declaration`; local-only resolution reports
`query_time_ns: null`, null absolute bounds, and `resolution: local_exact`.

The executable coordinator retains one narrow compatibility path for topology
providers created before scoped watermark declarations. If the exact
perspective/projection entry is absent, it derives the anchor from assembly
capture time minus the projection's declared watermark lag and uses the node
clock mapping. The response labels this
`watermark_source: legacy_capture_lag`. New providers must emit explicit
scoped watermarks and must not depend on this fallback.

With `ClockAlignmentPolicy.STRICT`, missing clock transforms, gaps in transform
coverage, and uncertainty that straddles a state transition remain unknown or
ambiguous. The core never treats equal raw timestamps from different clock
domains as equal instants, never drops uncertainty, and never silently falls
back to a different node, layer, perspective, projection, or timestamp.
`BEST_EFFORT` may use a recorded assumption, but the resolved basis must expose
that method and degraded quality. A relative request over several nodes resolves
to a `relative_capture_vector`; it does not claim a simultaneous wall-clock
snapshot.

Multi-node reconstruction evaluates the complete mapped uncertainty interval,
including every resource/lifecycle boundary inside it. It must not evaluate
only the interval center. If the window admits more than one state, the result
is ambiguous and carries the possible states; a stable but non-zero window is
best-effort rather than exact.

### Normalized conditions and outcomes

Device-specific status text is interpreted by the plug-in, not by the core.
`DomainEvent.outcome` is the normalized `success`, `failure`, or `unknown`
result. `SnapshotObservation` and `StateMutation` carry an optional normalized
`condition` plus `ConditionClass` (`healthy`, `degraded`, `error`, `absent`, or
`unknown`). A resource kind's `condition_field` tells generic tables and hovers
which plug-in property is the human-readable condition. The core stores and
renders these fields exactly; it does not search arbitrary `*status` fields,
apply error-word regular expressions, or infer create/delete semantics from an
action label. Missing normalization remains `unknown`.

### Relationships

Use explicit types such as:

- `owns` / `subordinate_to`
- `depends_on`
- `references`
- `cross_layer`
- `corresponds_to`

All domain entities remain plugin-declared resource kinds, including connector-
like entities such as a Glue resource. `ResourceKindDescriptor.presentation_tags`
may request generic UI treatments such as `connector`, `compact`, or `path-hop`;
the core must not branch on names such as ETG, ETE, DTE, Forwarding Group, or
Virtual Interface. Likewise, a next-hop relationship can target any declared
resource kind. Whether it represents another encapsulation group or IP routing
is plugin data, not a core enum or class hierarchy.

A resource kind may also provide an optional `ResourceIconDescriptor`. The icon
contains one SVG path, a numeric four-value view box, `stroke` or `fill` render
mode, and an optional stroke width. For example:

```python
ResourceIconDescriptor(
    path="M4 12h16M12 4v16",
    view_box=(0, 0, 24, 24),
    render_mode=IconRenderMode.STROKE,
    stroke_width=1.5,
)
```

The path is presentation metadata owned by the plug-in. The core accepts path
geometry only—never raw SVG markup, scripts, styles, or remote URLs—and falls
back to its generic resource glyph when the icon is absent or invalid.

A plugin may create additional derived resources, resource kinds, relationship
types, and causal-link types when they are needed to explain the input. It must
declare every emitted type in `PluginSchema` and attach stable identity,
provenance, quality, and evidence to each derived object. These declarations are
fixed for an analysis revision; changing them requires a new plugin/schema
revision. The core validates, stores, queries, and renders these objects
generically. It does not infer domain resources or correlations. The only
core-created node allowed for referential integrity is an explicitly marked
unresolved-reference placeholder, never a guessed domain entity.

Resource and relationship state changes belong in `apply()`. Cross-event causal
correlations belong in `correlate()`. This keeps ETG, ETE, DTE, Glue, protocol,
and any future vendor-specific semantics entirely inside the plugin while still
allowing the core to present a complete temporal model.

Event causality is a `CausalLink`, not a resource relationship. The core does not
propagate state through any relation automatically.

Every relationship mutation carries an effective raw/normalized time,
uncertainty, cause event (when any), and evidence. A target change is represented
as a remove of the old edge plus an add of the new edge at the same effective
time; there is no ambiguous one-to-many `replace` operation.

`ReadOnlyWorld.related()` accepts outgoing, incoming, or both directions and
streams complete relationship views (type, endpoints, attributes, provenance,
quality, validity, and evidence). `iter_states()` and `iter_relationships()` are
streaming scans with coordinator budgets. Reducers can therefore find reverse
dependents and implement one-to-many fan-out without losing edge metadata or
forcing a full-world list.

Every world exposes its resolved `WorldBasis`: an observed capture vector,
legacy reconstructed time, absolute-time mapping, or relative capture vector.
Resource views retain validity/capture ranges and evidence, so findings and
forwarding projection can preserve the actual observation anchors.

### Status perspectives and topology projections

`PluginSchema.status_perspectives` declares each independently reconstructed
layer-local view. A `StatusPerspectiveDescriptor` has a stable ID, label,
`layer_id`, and descriptive role (`intended`, `programmed`, `observed`, or
`other`). Role is presentation and policy metadata only; the core does not rank
roles or infer that observed hardware is ground truth.

Every stored observation, mutation, resource view, and relationship view may
carry a `StatusPerspectiveRef`. A plug-in may emit the local perspective ID;
the core qualifies it with the selected plug-in instance and immutable schema
digest when those identities are available. `ReadOnlyWorld.perspective_ref`
therefore makes the selected view explicit to reducers and projectors without
assuming that equal local IDs from different plug-ins are interchangeable.

`PluginSchema.topology_projections` declares named plugin interpretations of
which typed resources and time-valid relationships constitute connectivity.
Every `TopologyProjectionDescriptor` lists its supported status perspective IDs
and may name one display default. It also declares the generic status-source
combination operator (`all_required_usable` or `any_declared_usable`) when the
plugin delegates simple aggregation to the core; richer plugins may emit final
usability directly. The schema rejects duplicate IDs, undeclared
perspectives, and a default outside the supported set. The default is never an
authorization to substitute it when an API caller explicitly selects another
perspective.

When a host wires this capability, it calls
`PluginCapabilityExecutor.project_topology(TopologyProjectionRequest,
ReadOnlyWorld)`. The request names the selected projection and status
perspective, optional canonical seed resources, a hard `max_records` output
bound, and a cumulative `max_world_reads` input bound. The world has already
been resolved to the requested temporal basis and is wrapped by the executor to
enforce the smaller of request and core limits. The plug-in output is a
streaming iterable of `TopologyProjectionRecord` or diagnostics; the executor
returns a validated `TopologyExecutionResult`. This callable boundary is
implemented even though the current runtime-v2 session does not yet install a
topology provider.

Each projection record repeats the selected IDs and contains exactly one typed
payload:

- `TopologyResourceRecord` references one canonical `ResourceKey` and optional
  plugin role.
- `TopologyEndpointRecord` assigns a stable endpoint ID to one
  `TopologyEndpointReference`.
- `TopologyLinkRecord` assigns a stable link ID and connects two endpoint
  references, with explicit directionality.

An endpoint reference contains exactly one canonical resource key or one
`TopologyMatchReference`. A match reference has a namespaced matcher ID, bounded
typed arguments, and zero or more plugin-resolved canonical candidates. The
core treats matcher ID and arguments as declarative plugin data: it validates,
stores, and returns them but never implements or guesses the matching rule.

The common record envelope carries tri-state topology `exists` separately from
`TopologyUsability` (`usable`, `unusable`,
`degraded`, or `unknown`), source resource keys, plugin properties and field
unknowns, validity, provenance, quality, and evidence. The core verifies that
record projection/perspective IDs match the request and declared schema, checks
canonical references and limits, then materializes/serves the intervals. A
plugin must use `unknown` rather than omit a projected object merely because the
selected status perspective has no answer.

When a plug-in supplies a normalized topology resource in compact replay form,
`initial_status` and `initial_state` establish its first known values and
`changes[]` supplies time-ordered updates. Each applied change may update
`status` and merge `state`. It may also set the optional boolean `exists`
explicitly. When `exists` is omitted, the core recognizes the generic
`operation` values `create`, `add`, and `insert` as existence and `delete` and
`remove` as non-existence; an explicit boolean always takes precedence over
that inference.
A change with `state_changed: false` is a complete no-op for existence, status,
and state, even if it describes a failed delete or carries proposed values.
Replay order is `(time_ns, source_sequence, event_uid/change_id)`.
`source_sequence` is therefore required whenever one producer can emit several
changes at the same timestamp. A modify after deletion may update latent state
for later inspection/recreation, but it does not make the resource exist; only
an explicit `exists: true` or generic `create`/`add`/`insert` operation can do
that.

This order also governs timeline detail, topology change replay, and other
same-timestamp streams. `event_uid` or `change_id` is the stable final
tie-breaker; insertion order is never semantic. Order-dependent handles are
versioned. The current temporal cursor encoding accepts `tt2` and rejects older
cursor versions, while server-generated cluster IDs contain `server-v2` so a
client cannot mistake an old-order cluster for the current one. Both remain
opaque client values; authors must not parse either prefix.

The enclosing `valid_from_ns`/`valid_to_ns` interval remains authoritative and
half-open. No lifecycle change can make the resource exist before
`valid_from_ns` or at/after `valid_to_ns`. Within that interval, a delete may
create an absence gap and a later create may restore the same canonical
identity. A status such as `down` alone does not delete the resource. Status and
merged state are retained across an absence gap so a later recreation can
either reuse or explicitly replace them.

Topology history/change queries are also half-open:
`start_ns <= effective_time_ns < end_ns`. This applies to resource events and
relationship mutations alike. A boundary change is returned by the later of
two adjacent windows exactly once; a zero-width window is empty. Plug-ins must
not duplicate or offset boundary records to compensate.

An ambiguous relationship boundary therefore produces `exists=None` and a
possible link with unknown usability. It is never promoted to a definite link.

#### Multi-access connectivity domains

A shared subnet, broadcast domain, or other multi-access medium does not need a
special core hyperedge. A topology plug-in or federation linker projects it as
a canonical `TopologyResourceRecord` with a role such as
`connectivity-domain`. Each participating interface, subinterface, LAG, or
other plug-in-defined endpoint remains independently addressable and connects
to that domain through an ordinary temporal `TopologyLinkRecord`. This avoids
expanding one N-way medium into N-squared router-to-router links and preserves
multiple attachments from the same node.

The core validates, stores, pages, time-selects, and renders this bipartite
resource/attachment graph. It may aggregate generic existence, usability,
quality, provenance, evidence, and completeness, but it never derives a domain
identity from a prefix or display label. Prefix reuse across VRFs, VLANs,
tenants, sites, and VPNs makes such a merge unsafe.

Exact opaque keys are recursively type-tagged and serialized into a JSON-safe
normalized form. A UUID atom, its text form, a 16-byte atom, and a compound key
containing any of them remain distinct. Stable attachment identity is derived
from stable domain/member/revision/resource identity and an optional explicit
plug-in attachment key; plug-in run IDs are provenance and never identity.
Resource preview pagination is independent from bounded attachment evaluation.

The executable typed contract represents this distinction with `KeyAtom`.
Existing integer, string, byte, UUID, and compound `ResourceKey` values remain
valid. A plug-in uses the standard `opaque_int`, `opaque_uint`, `ipv4`, `ipv6`,
`uuid`, or `bytes` tag when a raw representation would otherwise alias another
meaning, or a bounded `plugin:<plugin-id>:<local-tag>` for a plug-in-specific
atom. The core validates tag syntax and the standard payload shape, preserves
the tag for equality and serialization, and never derives resource semantics
from it.

Plug-ins own the domain key and all networking semantics: IP prefix and address
interpretation; VRF or VPN scope; VLAN, LAG, subinterface, SVI, and physical
member composition; neighbor/route/interface inference; management and
loopback exclusion; and whether a one-sided domain is truly external. A domain
with one returned attachment means only `single_sided_in_query_scope` unless a
plug-in asserts `external` and the relevant projection coverage is complete.
VPN domains belong to a separate projection or presentation plane so an
overlay is not silently mixed with underlay adjacency.

At the normalized assembly boundary, construct
`TopologyPluginSemanticsDescriptor` from `plugin_semantics.role` and
`coverage_complete`. The role field is open, bounded plug-in vocabulary; the
descriptor returns `TopologyExternalClassification` only for
`TopologyDomainRole.EXTERNAL` with boolean `coverage_complete=True`. A
non-null classification therefore proves both declarations. Missing, false,
integer, or string lookalikes do not prove external coverage. The complete
`plugin_semantics` envelope must be a bounded string-keyed, strict JSON value:
non-finite numbers, binary or arbitrary Python objects, reference cycles, and
values beyond 128 top-level fields, 128-character top-level keys, 16 container
levels, 1,024 items per nested container, 4,096 total value units,
65,536-character atoms, or 4,096-bit integers fail before merge.
Merge-critical equality preserves scalar types, so integer `1` never aliases
string `"1"`.

The executable v1 `TopologyProjectionDescriptor` declares topology semantics
and supported status perspectives; it does not yet carry reusable
browser-profile fields. When the coordinator or assembly profile adapter
publishes a reusable profile around a selected plug-in projection, that
profile declares bounded `presentation_roles` explicitly. Use the exact role
token `vpn` when the profile is appropriate for the generic VPN-view
suggestion; do not rely on `evpn`, `l3vpn`, VRF, projection, protocol, or
resource names being parsed by the core. The profile may also declare safe
`empty_action_label` text. These fields influence only generic presentation
and selection. They do not add topology, route, or reachability semantics.
Adding them directly to a node plug-in requires a versioned protocol addition;
plug-ins still cannot provide HTML, CSS, JavaScript, or navigation URLs.

For a domain that the plug-in knows is safe to display inline when it has two
participants, set `TopologyResourceRecord.presentation` to a
`TopologyResourcePresentation` whose `two_participant_shape` is
`TopologyTwoParticipantShape.COMPACT_EDGE`, and expose the equivalent
`topology_presentation` metadata in normalized projections. This is a display
preference, not a topology claim: the domain resource and every attachment
link remain canonical, temporal, and independently inspectable. The plug-in
should provide a human-readable reason plus its inference rule, confidence,
evidence, and provenance.

The core fails closed. It uses the compact line only for a conflict-free
physical domain with complete returned current membership and exactly two
distinct current participants. Otherwise it keeps the domain vertex. A
filtered query that happens to show two members of a larger shared medium must
therefore not acquire compact-edge semantics. The core validates cardinality
and completeness and renders the generic shape, but never infers this choice
from `/30`, an interface type, protocol, VLAN, VRF, address overlap, or a
display name. `DOMAIN_NODE` is the default and is appropriate for shared media,
VPNs, one-sided domains, and any uncertain projection.

Pairwise inter-node links may remain as a compatibility projection for route
segments. Links derived from a connectivity domain should retain references to
that domain and the ingress/egress attachments that justify them. An
independently derived route-only link instead declares its compatibility role
and that it is not subnet-membership evidence; the physical view suppresses it
when an explicit domain projection is available. Removing either compatibility
form requires a versioned route schema that can name attachment transitions
directly.

Validate each such claim with `InterNodeLinkPresentation`. A plug-in may set
`route_trace` to `InterNodeRouteTraceRole.INCLUDE` or
`InterNodeRouteTraceRole.OVERLAY`; omission defaults to `include`.
Serialize the typed result as
`{"route_trace": presentation.route_trace.value}` rather than placing the
dataclass itself in the JSON envelope.
`InterNodeRouteTraceRole.CONFLICT` is response-only and a plug-in declaration
of it is invalid. When two otherwise valid peer claims disagree, core emits
wire value `conflict`, projection role `presentation_conflict`, and unknown
operational status instead of guessing whether the link is a physical route
hop. These normalized wire strings are stable compatibility values.

A forwarding candidate that crosses a connectivity domain must retain a typed
declarative topology reference rather than only a derived pairwise line. The
plug-in owns the matcher ID/version, opaque domain key, local/remote attachment
resource IDs, candidate selection, decision/disposition, and explanation. Core
may join the reference only through an advertised exact-token contract. The
generic join requires exactly one current usable domain, exactly one current
usable source attachment, exactly one current usable target attachment, and
complete non-truncated evidence. Missing, ambiguous, conflicting, down, or
truncated evidence stays unresolved. Core must not recover a match from a
prefix, address, VLAN, interface name, label/SID, node pair, or
`resolution_text`.

The exact domain-key profile type-tags every atom and container, including
mapping keys, so missing is distinct from explicit null and integer `1` is
distinct from string `"1"`. It accepts only finite floats and is bounded to
four nested container levels, 32 items per container, 1,024 total value units,
4,096-character/string or byte payloads, and 4,096-bit integers. A cyclic,
unsupported, non-finite, or over-bound key is invalid evidence and cannot
resolve a connectivity domain.

The topology hook supplies raw Python values; the core applies the profile once
and stores the tagged normalized representation. A resolver that consumes
stored or API projection data validates and canonicalizes that normalized
representation directly. Transport tag wrappers do not consume logical
container depth. Unknown tags, missing or extra tag fields, invalid UUID/base64
or numeric encodings, non-canonical mapping order, duplicate canonical mapping
keys, and a candidate `typed_key` that does not reproduce its normalized key
are invalid evidence. A normalized value must never be passed back through the
raw-value normalizer or accepted by heuristic JSON-shape matching.

#### Federating different node plug-in sets

An assembly may contain nodes whose active plug-in sets, resource vocabularies,
projection IDs, perspective IDs, and versions are completely different. The
coordinator invokes each node against its own immutable revision and qualifies
every semantic selection by the producing plug-in run. A plug-in must not rely
on another node using the same local descriptor IDs. Identical local
`ResourceKey` values remain distinct because assembly references also contain
member and revision IDs.

A local topology plug-in can export bounded endpoint claims. A claim contains a
stable local endpoint reference, a namespaced and versioned claim-contract ID,
an opaque canonical value, local/remote role, validity, quality, provenance,
and evidence. The plug-in owns extraction and normalization. The core validates,
indexes, pages, and transports claims but does not interpret an IP address,
system ID, interface alias, label, SID, or proprietary peer key as a connection.
The executable form is a node-local `ConnectorClaim`: its ordered
`KeyValue` arguments use `KeyAtom` whenever a scalar representation would be
ambiguous, and it deliberately has no remote-candidate field. The coordinator
qualifies the local endpoint with `GlobalResourceRef` and wraps the pair as a
`FederatedConnectorClaim`; member, immutable revision, and plug-in-instance
scope therefore cannot be lost during assembly matching.

Cross-node matching beyond an explicitly declared exact-token contract belongs
to a separate allowlisted federation/linker plug-in. It declares the claim
contracts it accepts and emits validated inter-node link records with candidate
sets and a resolution of matched, ambiguous, unresolved, or conflict. Reciprocal
evidence requirements, one-sided observations, alias rules, and link usability
are linker semantics. The core preserves all candidates and never resolves
ambiguity by picking the first match.

Both paired claims also declare their normalized `link_type`. If the values
disagree, the coordinator returns one deterministic conflict record with
`link_type: "unknown"`, the sorted distinct `claimed_link_types`, operational
status `unknown`, and reason `plugin_link_type_mismatch`. It never chooses the
left claim, right claim, or iteration order. A presentation-role disagreement
is likewise fail-closed and cannot be promoted into a physical route hop.

`ConnectorMatchPolicyDescriptor` makes the boundary executable:
`exact_token` authorizes only equality over the complete ordered typed argument
tuple, while `linker` names the allowlisted `FederationLinkerPlugin`. Only the
latter receives a bounded `FederationLinkRequest`. It returns bounded
`FederationLinkResult` records and `FederationMatchCandidate` values; it cannot
read node worlds, raw artifacts, or mutate a node-local claim.

Multi-node watermark scope includes member ID, plug-in run, projection, and
perspective. Relative assembly queries resolve those watermarks independently;
they are capture vectors and do not imply a simultaneous network state. Missing
or failed members remain reason-coded coverage records unless the request marked
them required and explicitly demanded an all-or-nothing result.

Topology objects remain ordinary canonical resources and relationships with
validity intervals, provenance, quality, unknown fields, and evidence. Plugins
own topology inference, peer matching, interface aliases, and the mapping of
proprietary state to generic `usable`, `unusable`, `degraded`, or `unknown`
projection values. The core owns storage, historical selection, pagination, and
the response envelope. Missing selected-perspective status yields `unknown`; it
does not remove an otherwise supported topology object. A dependency edge is
not connectivity unless the selected plugin projection says it is.

Topology projection and status perspective are independent request choices.
For example, an IS-IS/LLDP-derived connectivity projection may be evaluated once
with control intent and again with observed hardware status while retaining the
same canonical topology identities. Reachability ground-truth policy is a third,
separate route-tracing choice and must not be encoded into either descriptor.

### Provenance, quality, and coverage

Provenance answers "where did this fact come from?" and quality answers "how
strongly does the evidence determine it?" They are orthogonal. The canonical
vocabularies are the `Provenance` and `Quality` enums; do not use "certainty" as
an alias. A plugin manifest's reconstruction value is only a default capability,
while every output and changed field carries its actual value. `ChangeSet`
coverage reports count exact, best-effort, ambiguous, and unknown outputs for a
named scope. Skipped/omitted scope requires a reason-coded diagnostic or unknown
record. APIs and exports preserve these values rather than flattening them.

### Display and query metadata

`describe()` returns resource/property/relation descriptors used for lane
choosers, labels, filtering, redaction, and selective indexes. Plugins normalize
raw states into their own declared properties plus the deliberately small core
enums such as `ConditionClass`, `Outcome`, provenance, and quality. Names such
as admin state, operational state, reachability, or programming state remain
plug-in fields rather than universal core semantics. The web theme maps the
normalized presentation class to accessible colors; plug-ins must not emit CSS
or assume a particular color palette. Any descriptor field named `color` is
transported only as a validated six-digit `#RRGGBB` value; an invalid value is
replaced by a deterministic core palette color at both the server and browser
boundary.

Every resource kind referenced by a public resource, interval, or event must
have a descriptor in that immutable plug-in schema. Public projection fails
closed for an undeclared kind; it does not guess an empty property policy.
Fields declared `sensitive` are removed recursively from resource state, typed
keys, intervals, events, summaries, search documents, and the browser bootstrap
envelope. Each non-sensitive property is browser-visible only when its
`PropertyDescriptor.client_visible` value is true; undeclared and
`client_visible: false` resource fields are omitted and excluded from search.
If `condition_field` names a sensitive or non-client-visible property, the core
reports the generic condition as `unknown` in resource views, intervals, event
effects, and top-level event condition/status fields rather than copying that
value into `status`.

A dotted property name is a relative path inside plug-in-owned property
payloads. Redaction follows that path through nested mappings and lists and
also removes an exact literal dotted key. The property policy is never applied
as a global key blacklist. Core-owned structural fields such as
`revision_id`, `node_id`, `resource_id`, `kind`, `label`, `action`,
`affected_resources`, timestamps, interval bounds, schema descriptors, and
workspace capabilities remain present and retain their core value even when a
plug-in declares a property with the same name. The scoped payload containers
include `state`, `key`, `properties`, `attributes`, `before`, `after`, and
`result`.

Public `evidence`, `provenance`, `unknown_fields`, and `incarnation` values are
typed metadata envelopes, not plug-in extension bags. Core projects only the
normalized scalar metadata fields defined by the API; unknown metadata keys or
nonconforming shapes are dropped. `unknown_fields` is an ordered list of
reason-coded records with bounded evidence references, and an incarnation is a
non-Boolean string or integer. Device-specific values belong in declared
properties and do not become public by being nested under a metadata key.

Event payload policy is resolved from the event's explicit `resource_kind`,
typed subject/effect resource kinds, and every canonical resource reference in
`affected_resources`, `resource`, and `resource_id`. The core looks those IDs up
in the immutable resource catalog. Generic event `kind` names the event type;
it is not a resource-kind hint. When an affected reference is unresolved, no
resource kind is determined, or an involved kind lacks a policy, event
publication uses the conservative union of declared sensitive fields.
The nested `subject`, `subjects`, `affected_resources`, `effects`, and
`relationship_effects` records use explicit core allowlists. Unknown children
are dropped, and their core scalar fields reject container-shaped values;
plug-in-specific data belongs only in a declared property payload.

Bootstrap serialization uses a core-owned allowlist of normalized model and
workspace fields, so plug-in caches or parser-private dataset keys cannot become
client data merely because they lack a leading underscore. Property redaction
is then applied only inside the allowlisted plug-in payload leaves. This
core-envelope invariance is required across the workspace bootstrap,
point-in-time resources, range summaries, and event-query responses.

`PluginSchema.source_record_groups` declares zero or more
`SourceRecordGroupDescriptor` values. Each supplies an opaque plug-in-owned
group ID plus safe label, description, and default inclusion state.
It may also provide a safe `copy_action_label` for copyable records in that
group; the label does not grant access or make every group record copyable.
`SourceRecordTypeDescriptor.stream_group` is a reference to one of those
declared IDs, not a free-form core category. The core validates the reference;
the browser renders generic controls and converts selected groups into explicit
source-type filters.

A source-record group is presentation/query metadata only. It is not a
Babeltrace stream, clock domain, storage partition, or event semantic. For
example, the demo plug-in may declare groups named `ctf` and `external`, but
those are demo vocabulary, not core enums. The core never derives a group from
`source_type`, a record label, or CTF knowledge.

### Relationship-bundled resource-table views

`PluginSchema.resource_table_views` lets a plug-in place related resources
closer together without introducing a core domain hierarchy. A
`ResourceTableViewDescriptor` declares root kinds and one to three
`ResourceTableRelationLevelDescriptor` hops. Each hop supplies a label,
declared relationship types, direction, and optional target-kind filter. The
view also declares safe columns, default expansion depth, and hard root/child
bounds.

Resource-kind presentation remains declarative too. Nested rows use each
referenced `ResourceKindDescriptor` for its type label, validated icon,
presentation tags, key fields, and default state fields; a table view may
override the shared columns with explicit field projections and value formats.
For example, a plug-in can declare a Virtual Interface root, traverse one of its
own adjacency relationship types to its own Neighbor kind, and choose which
interface and neighbor fields to show. The core has no built-in interface,
neighbor, or protocol kind names.

The core validates those references, resolves the relationship path at the
requested time, checks every endpoint lifecycle, and returns a bounded nested
projection. It does not inspect resource names or key-field names. A temporary
child is present only while both its lifecycle and the declared edge are active.
A repeated child may appear beneath multiple roots as separate presentation
occurrences while retaining one canonical identity and one timeline lane.

A plug-in may use a compound child `ResourceKey`, such as
`(("parent_resource_id", parent_id), ("path_id", path_id))`, and emit an
exact `owns` relationship between the parent and child keys. The key keeps the
child independently addressable; the relationship, not key parsing, controls
grouping and temporal ownership.

The packed scale-demo adapter additionally accepts optional `KEY_JSON` and
`STATE_JSON` object columns in `resources.table.txt`. They overlay the legacy
compatibility columns and preserve arbitrary plug-in-owned JSON values,
including nested typed-key wrappers, numbers, booleans, and arrays. This is a
demo transport detail rather than a domain schema: the plug-in still declares
the meanings and presentation of those fields through `PluginSchema`.

### Dashboard descriptors

`PluginSchema.dashboards` lets a plugin compose resource-specific dashboards
from core-owned widgets. A `DashboardDescriptor` supplies a stable ID, title,
description, one or more statistics or tables, and presentation defaults:
`default_open`, `collapsible`, `default_expanded`, and `movable`. Dashboard
IDs are unique within the schema, and every referenced resource kind must be
declared by the same plugin revision.

A `DashboardStatisticDescriptor` selects resource kinds and one of the common
aggregations `count`, `count_distinct`, `sum`, `average`, `minimum`, or
`maximum`. Optional declarative filters support equality, membership, field
existence, and containment. Non-count aggregates name a bounded field path such
as `state.metric`; display units and numeric precision are metadata.

A `DashboardTableDescriptor` selects resource kinds, bounded row count, optional
sort field/direction, and one or more `DashboardColumnDescriptor` field
projections. Common value formats are `auto`, `text`, `number`, `boolean`,
`status`, and `resource`. Unless `include_absent` is set, both widget types
exclude resources that do not exist at the selected time.

Dashboard equality retains scalar types, treats transported lists and
in-process tuples as the same sequence shape, and compares mappings without
depending on insertion order. Evaluation is bounded to 16 nested container
levels, 1,024 items per container, 4,096 comparison units, 65,536-character or
byte atoms, and 4,096-bit integers. Cyclic, unsupported, or over-bound values
are excluded from filters and `count_distinct`; its `sample_count` reports only
comparable values. Non-finite floats remain explicitly tagged comparison
values, but numeric aggregates exclude them.

Field lookup distinguishes absence from an explicit null. A present generic
envelope field wins even when null and is not replaced by a state/key fallback.
Ordinary comparisons fail closed on a missing field; `exists` tests presence
and defaults to `value: true`; explicit null participates in equality and
`count_distinct`; and a missing projected table column is omitted. Numeric
aggregates accept only finite integer/float values and exclude booleans,
numeric strings, null, and non-finite floats. With zero numeric samples,
`sum` returns `0`, while `average`, `minimum`, and `maximum` return null; all
report `sample_count: 0`. `max_rows` is an exact non-boolean integer in
`1..500`.

The core validates and serializes these declarations, calculates their values
from the generic point-in-time resource query, escapes every value, and renders
the common controls. Plugins do not provide markup, scripts, styles, URLs, query
code, or callbacks. This keeps resource semantics in the plugin without making a
plugin part of the browser trust boundary.

Serialized descriptors are validated again at the query boundary. A malformed
descriptor produces a bounded structured `descriptor_errors` result and no
partially evaluated dashboards rather than an HTTP 500 or silent coercion.

The browser presents all descriptors in an index and opens the
`default_open` modules at the end of the page. Open/closed, expanded/collapsed,
and user-defined order are local presentation state. Moving or collapsing a
module never changes the plugin schema or the analysis revision; a reset restores
the descriptor defaults. A non-collapsible module must be expanded by default.

### Determinism

For identical artifacts, configuration, and plugin build, output must be stable:

- Stable event UID derived with
  `derive_event_uid(plugin_id, parser_id, source_ref, local_discriminator)`.
  The optional discriminator separates multiple domain events from one source
  record without aliasing integers, strings, bytes, or UUIDs.
- Stable canonical resource keys.
- Stable record ordering within a source.
- No wall-clock reads, network calls, random IDs, or hidden global state in parse/reduce.
- Diagnostics use stable codes; human text may evolve only with plugin version.

## 4. Streaming and batching

The protocol uses iterables to keep the reference dependency-free. The production
worker should convert records into bounded Apache Arrow batches.

- Never return one list containing the whole trace.
- Bound batch rows and serialized bytes.
- Apply backpressure from coordinator to plugin.
- Validate schema and maximum property depth/size per batch.
- Store malformed-record diagnostics and continue only when the plugin declares
  the error recoverable.
- Avoid per-event ORM entities and per-row RPC calls.

Correlation never receives the whole trace. The core creates a
`CorrelationReader` bound to one `CorrelationWindow`; all its indexed queries are
clamped to that range and share one cumulative `max_events` budget. The plugin
may narrow by layer, event type, subject, and per-call limit. Exhaustion is
observable through `remaining_event_budget` and must produce ambiguous/unknown
output plus a stable diagnostic, never an apparently exact partial result.
`world_at()` has its own cumulative budget and rejects timestamps outside the
bound window; it never silently clamps to a different time.

Topology projection follows the same streaming rules. `max_records` is a total
coordinator-enforced budget across resource, endpoint, and link payloads, not a
per-type allowance. Exceeding it produces a bounded diagnostic/partial result;
it must not return an apparently complete topology. Match arguments, candidate
sets, source-resource references, property depth, and serialized bytes have
independent core caps.

If a plugin needs Polars/Lark/TextFSM, those libraries remain in its worker image;
they are not forced on every plugin.

### Canonical wire values

Arrow batches use core-owned schemas with fixed scalar columns. Variable
properties are canonical JSON UTF-8 within a bounded Arrow binary/string column,
plus plugin-declared projected typed columns for hot queries. The JSON encoding
reserves tagged objects:

```json
{"$rda":"bytes","base64":"AQIDBA=="}
{"$rda":"uuid","value":"123e4567-e89b-12d3-a456-426614174000"}
```

Map keys are strings and canonical output sorts them. Reject non-finite floats,
invalid UTF-8 text, excessive depth, and oversized property values. Arrow carries
declared timestamps as signed `int64`; public JSON APIs encode core-owned
nanoseconds and other unsafe 64-bit integers as decimal strings. This conversion
is owned by the core, not reimplemented differently by each plugin. A key ending
in `_ns` inside an opaque plug-in mapping is not thereby a core timestamp: the
correlation-report wire preserves that key's bounded JSON value and type.

## 5. Version selection

Probe results contain confidence and reasons, but confidence is not permission to
guess. Each result also carries the plug-in-owned `match_kind` (`exact`,
`compatible`, or `none`); the core does not parse or compare vendor software
version strings. In the implemented durable queue, `none` is excluded; no
remaining candidate fails the import; exactly one remaining candidate is
selected only when `auto_select` is enabled; and every multi-candidate set
waits for an explicit choice unless the caller supplied a preferred plug-in ID
that matched exactly once. Confidence orders candidates but never selects
among several candidates.

`validate_probe_report()` is the single complete executable contract at every
boundary and delegates its optional result to `validate_probe_result()`.
Confidence is a finite number from `0` through `1`. `reasons` contains 1 to 128
non-empty strings of at most 1,024 characters. Optional `detected_platform` and
`detected_software_version` strings contain 1 to 256 characters. Probe
diagnostics are exact `PluginDiagnostic` values with plug-in origin, probe
stage, bounded code/message/evidence, and evidence restricted to the probed
inventory. The same `validate_plugin_diagnostic()` contract is reused by
parser ingestion and optional-capability execution, with each runtime adding
only its contextual aggregate budgets. NUL is rejected. A forged or mutated
dataclass is revalidated by the host and process parent; author validation and
durable ingestion do not carry separate field bounds.

Core persists the sorted candidate-set hash with the exact selected plug-in ID,
version, and executable identity. A trusted loader may register an immutable
package/artifact digest. Otherwise core fingerprints the defining import scope.
A regular package uses its first regular ancestor only when no namespace
ancestor precedes it. If any PEP 420 namespace precedes the defining module,
the first namespace ancestor is the boundary even when a later component is a
regular package. Every one of that namespace portion's runtime `__path__`
search locations participates in import-precedence order. A runtime search path
that no longer contains the defining module fails closed rather than narrowing
to one file. Both
forms use `package-sha256:<digest>` over a deterministic, bounded sequence of
filesystem entries. A genuine top-level module has no package scope and uses
the distinct `module-sha256:<digest>` identity over that module file; core never labels a
one-file fallback as a package identity. Registry-derived package and module
identities are recalculated immediately before probe and ingestion.
Sourceless `.pyc`/`.pyo` modules have no core-derived identity: Python bytecode
may embed a build-host source path, so hashing it would violate relocation
stability. A trusted loader MUST provide an immutable artifact digest if such a
deployment is intended for durable execution.

The bounds are shared across every search location: 4,096 fingerprinted
entries (regular files, ordinary directories, or aliases), 8,192 examined
paths, 32 MiB per file, 128 MiB total, and 4,096 UTF-8 bytes per relative path.
Empty directories participate because they can change namespace imports and
resource-existence checks. Each file read is capped at its opened-handle size
plus a one-byte growth sentinel; handle and path identities must remain stable,
so concurrent growth cannot consume past the declared limits. Search-root
ordering is encoded without host paths, so
relocation does not change an identity while import-precedence changes do.
The first namespace ancestor is a deliberately conservative boundary so a
parent-relative helper cannot escape the identity. Authors who need a narrower
scope should publish the exported plug-in and its helpers under a top-level
regular package rather than below a shared namespace.
Contained symbolic-link or
Windows-junction aliases are recorded by package-relative target but never
traversed; their canonical targets are fingerprinted normally. This makes
contained cycles finite and installation-path independent. Aliases that
escape the package root, changing files, and over-bound packages fail closed.
Actual VCS/cache directories are pruned before traversal. The basename is not
a general exemption: a regular file or contained alias named `.git`, `.hg`,
`.svn`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, or `.ruff_cache`
participates in identity, and an escaping alias with such a name still fails
closed. Registries fail closed by default when no executable file is
inspectable. A compatibility-only local/test embedding may explicitly pass
`allow_manifest_identity=True`; the headless CLI and every durable
`ControlPlane` reject that fallback before state is created.

Explicit selection requires an idempotency header and the client must echo all
four returned values. Core durably binds the scope, key, request digest, and
selected import. Replaying the exact request returns the current descriptor
even after the state advances; reusing a key for another request is rejected.
A fresh key may confirm the same stored exact selection but cannot change it.
Resume is allowed only from a failed durable job within its attempt budget. It
re-enters fixture admission or revision publication when that exact operation
was already staged and never reuses partial output created by another
registered identity.

Composition is useful: a family plug-in may provide common declarative artifact
locators and status parsers, while a release adapter overrides resource mappings
or reducers. Archive recognition, traversal, materialization, and quota
enforcement remain core operations; a plug-in never supplies an archive parser.
The current reader supports one regular file, directory, tar, or ZIP container.
Recursive nested-codec peeling and an outer-to-inner codec-chain record belong
to a future nested-codec extension, not the current runtime-v2 or durable
ingestion contract. The final bundle still has one recorded, reproducible
manifest/hash.

## 6. Process and security model

The plug-in remains trusted application code, not a sandboxed parser, while
the dump remains hostile input. The optional durable profile uses
transactional SQLite queue claims, renewable fenced leases, heartbeats, and
restart recovery. Queue coordination workers are application threads, but
both the complete allowlisted probe and selected ingestion run in a fresh
child created with Python's `spawn` start method. `DurableIngestionPipeline`,
the durable `ControlPlane`, `router-dump-server`, and `router-dump-ingest`
default to this process mode. An embedding may explicitly select `inline` only
for trusted local/test code. Inline execution is synchronous and deliberately
makes no timeout or
bounded-shutdown promise; core does not create an unkillable helper thread and
misreport its queue wait as cancellation. Only process mode is a killable fault
boundary.

Every in-process executable plug-in boundary MUST rethrow `KeyboardInterrupt`,
`SystemExit`, and `GeneratorExit` unchanged and MUST contain every other
`BaseException`. Validator failures become bounded author diagnostics;
capability failures become fixed `PluginCapabilityExecutionError` messages;
registry probe failures remove only that candidate; and trusted inline
ingestion routes failures through its existing durable worker classification.
No public failure text may interpolate a plug-in exception. Core snapshots the
validated manifest identity during registration instead of repeatedly invoking
a plug-in-owned manifest descriptor. These sites share one dependency-free
process-control exception vocabulary so HTTP, validator, capability, and
ingestion boundaries cannot drift independently.

The default child deadline is 300 seconds, validated within 0.05 through
86,400 seconds. It covers child startup, plug-in execution, bounded result
transfer, and clean exit; the headless command caps it to the command's
per-import timeout. On timeout core terminates, waits two seconds, kills if
needed, waits two more seconds, and reaps the child. The import records
`plugin_execution_timeout`. Startup, crash, invalid child protocol, or
reported execution failures record `plugin_execution_failed`. Any partial
ingestion spool file is removed and no partial revision is published.

Child IPC is canonical JSON metadata bounded to 1 MiB. The ingestion child
writes its canonical dataset into one unique parent-selected spool path and
returns revision/node identity, SHA-256, byte size, and counts. The parent
renews the fenced lease, verifies regular-file status, size, and digest, then
content-addresses and publication-stages the dataset. Registry-derived
package identities are re-hashed inside the child immediately before probe or
ingestion. Loader-supplied immutable identities remain trusted loader
assertions.

The plug-in and custom coordinator object graph MUST be importable and
spawn-picklable. A child process is a killable fault boundary, not a security
sandbox: it inherits the host user's filesystem, network, environment, and OS
privileges. The executable boundary currently also provides:

- Read-only selected artifact handles.
- Session-private scratch copies bounded by the artifact quotas.
- No original host path through the standard `ArtifactReader`.
- Count, nesting, value, evidence, and output limits at coordinator/executor
  validation boundaries.
- Only core may normalize, publish, or persist validated output.

Production deployment MUST add disposable, hardened Linux workers or
containers per job or bounded job group, no
network/secrets/database socket/host paths, and CPU, memory, file,
child-process, output, inode, and wall-time limits. Native Babeltrace failures
must terminate only that worker. The shipped child-process boundary supplies
kill/reap and a wall deadline but not those sandbox/resource controls; a
built-in/default CTF decoder is also not implemented by the current
runtime-v2 slice.

`ArtifactReader.materialize_private_path()` supports a single native input;
`materialize_private_tree()` reconstructs a selected logical subtree for
Babeltrace and other multi-file readers. Neither returns an application or
host-global path.

The current `CoreArtifactReader` recognizes a top-level tar or ZIP by inspected
content, inventories regular members, and streams selected members to private
materializations. It never calls `extractall()`. It rejects unsafe or
non-portable names, links/devices/special members, collisions, and configured
member/depth/byte/compression-ratio overruns. Plug-in locator or role hints
cannot select a codec or relax those checks, and plug-ins may not open or
extract an archive themselves.

If the future nested-codec pipeline uses Python tar extraction rather than the
current member-streaming reader, every tar layer MUST explicitly apply
`filter="data"` or `tarfile.data_filter` before the stricter policy above.
Nested codec detection, codec-chain recording, and that extraction/filter path
remain future work.

## 7. Forwarding IR

The manifest advertises supported core forwarding IR versions. IR v1 is a
discriminated union of `VrfForwardingState`, `FibEntry`, `NextHopGroup`,
`NextHop`, `FailoverGroup`, `Adjacency`, `TunnelAction`, and
`InterfaceForwardingState`. Cross-record references are canonical typed keys;
addresses/prefixes and allowed target kinds are core-validated. A mutation has
an IR version, operation, effective time/uncertainty, provenance, quality, and
evidence plus the world basis. `upsert` requires a same-key record and `delete`
forbids one; there is no forwarding `unknown` operation (unknowns live in record
quality/unresolved references). `FibEntry.vrf` and `Adjacency.vrf` reference a
typed VRF key. Plugins normalize proprietary preference/tie rules into a
lexicographic `selection_rank` (lower wins), exact selected state where known,
and explicit multipath group; equal rank by itself does not imply ECMP.

Persistent forwarding projection and trace-time packet evolution are separate
capabilities. `FORWARDING_PROJECTION` describes the time-indexed forwarding
objects above. A plug-in that also declares `FORWARDING_TRACE` implements
`resolve_forwarding_step(request, world)` and answers one bounded, node-local
`ForwardingStepRequest` with a `ForwardingStepResult` or diagnostic. The trace
hook does not return an end-to-end path, inspect another member, or replace the
projected FIB. Conversely, opaque `TunnelAction.parameters` in the persistent
projection are not an executable packet transition unless the plug-in declares
the corresponding trace-time before/after state.

`project_forwarding(request, world)` is a deterministic streaming bootstrap.
`ForwardingProjectionRequest` carries the negotiated IR version, one fully
qualified `StatusPerspectiveRef`, an optional bounded `ChangeSet`, and hard
`max_records`/`max_world_reads` budgets. For later calls, `changes` contains one
bounded change set and the plugin yields only affected upserts/deletes. Batches
follow the same backpressure and size rules as other outputs. Conformance
compares a delta-maintained projection with a clean full projection, checks
removal of stale objects, and rejects invalid references, perspectives, budget
overruns, or IR versions.

### Coordinator-normalized node route choices

The generic node browser may expose a bounded route-choice capability derived
from the selected node plug-in's normalized projection. This is a coordinator
adapter, not a new v1 `AnalyzerPlugin` hook. A production integration normally
derives it from `FORWARDING_PROJECTION`; a specialized versioned projection
may supply an equivalent catalog.

When a plug-in projection participates in this adapter:

- each `route_id` is non-empty, opaque, unique within the immutable revision,
  and stable for that projected route decision;
- every advertised row is qualified by the exact node and revision and carries
  the provider identity;
- the projection owns destination vocabulary, route family/type, VRF,
  labels/SIDs, encapsulation, candidate semantics, and explanation;
- the coordinator advertises only executable basis kinds and validates that a
  resolve request selects an exact advertised `route_id`; and
- an unknown ID, mismatched revision, duplicate row, or unsupported basis
  fails closed. Core and the browser must not infer a substitute destination or
  select a route by display text.

The plug-in never supplies route URLs, HTML, JavaScript, or a browser control.
A point-in-time member snapshot must include a matching bounded node-local
response if it advertises a route choice; otherwise route resolution is
unavailable in that snapshot. See `docs/api-contract.md` for the normalized
capability and request payload.

A route-table projection may also contain a local or otherwise inventory-only
row with no declared end-to-end candidate. Such a row remains visible data but
must be marked `traceable: false`, carry an empty `trace_query`, and may provide
a bounded `trace_unavailable_reason`. Neither coordinator nor browser may infer
a trace target from its destination string, route type, or local forwarding
action.

### Packet state, transitions, and MTU

`ForwardingPacketState` is the protocol-neutral packet snapshot used by the
trace-time contract. Its `layers` are ordered outermost to innermost. Each
`ForwardingPacketLayer` has a stable identity within the branch, one
plug-in-owned `contract_id`, bounded typed fields, an optional declared byte
size, and explicit completeness. A plug-in may use one layer per MPLS label, an
SRH layer with an ordered SID field, an IP tunnel wrapper, a VPN context, or a
proprietary layer. Core validates bounds and exact identity only. It never
decides that a label is an SR-MPLS SID, infers PHP from a label value, parses a
SID behavior, computes tunnel overhead, or assigns meaning to a VPN layer. The
human `label` is presentation-only and is excluded from layer equality,
hashing, packet continuity, and structural change detection.

`ForwardingPacketTransition` records one node-local step with exact `before`
and `after` snapshots, an opaque `action_contract_id`, plain display label,
actor, contributions, and one normalized `ForwardingPacketDisposition`:
`continue`, `deliver`, `drop`, `punt`, `replicate`, or `unknown`. This
disposition is a trace result and is distinct from the forwarding-mutation
operations above. The node plug-in owns the actual semantics: push, swap, pop,
PHP or explicit-null behavior, SR segment processing, decapsulation and
relookup, fragmentation or discard behavior, and the explanation/evidence for
that decision. Core's `diff_forwarding_packet_states()` reports only added,
removed, changed, and moved layer identities plus whether both packet
identities were complete. `moved` means a relative reorder among retained
layers, not the absolute index shift caused by adding or removing an outer
wrapper.

`evaluate_forwarding_packet_trace()` validates one bounded transition chain.
Every complete transition's `before` state must equal the preceding `after`
state. A complete mismatch is a contract error. An explicitly incomplete side
retains the branch with `unknown_incomplete` continuity; core does not invent
the missing transformation. `max_steps` is independent from the hop and
recursion limits used by `evaluate_forwarding_traversal()`. Terminal
`deliver`, `drop`, `punt`, and `unknown` dispositions stop the branch.
`replicate` also stops the current linear branch with a typed branching
request; an orchestrator may expand the declared copies within its candidate
and branch budgets. A terminal disposition must be the final transition in the
supplied linear chain; a suffix after it is a contract error. A chain ending
only in `continue` is
`continuation_required`, not delivered or resolved.

Packet size comparison is exact-basis only. A plug-in may attach a
`ForwardingSizeObservation` to the packet state and a
`ForwardingMtuConstraint` to a transition. Both name an opaque
`basis_contract_id`, such as a platform buffer length or L3 packet length.
`evaluate_forwarding_mtu()` returns `fits` or `exceeds` only when both values
are complete and the IDs are identical. Missing/incomplete evidence returns
`unknown`; unequal basis IDs return `unknown_basis_mismatch`; no constraint
returns `not_declared`. Core performs the integer comparison and reports the
known excess bytes. Transition evaluation compares the declared `after` packet
size with the transition's MTU constraint. The plug-in owns the measurement
basis, effective MTU, encapsulation overhead, fragmentation rules, and
resulting packet disposition.

### Step requests and counterfactual steering

`ForwardingStepRequest` fixes one step ID, member, qualified status
perspective, forwarding object, current packet state, typed local lookup
context, optional ingress resource, at most 64 steering rules, a bounded
candidate limit, and the negotiated IR version. `ForwardingStepResult` must
echo that step ID and supplies exactly one transition plus the selected
candidate, next forwarding object/context, recursive/terminal flags, and
quality. A `continue` transition is non-terminal and requires a next
forwarding object. Every other disposition is terminal for the current linear
branch and must not supply a next object or lookup context.
`validate_forwarding_step_result()` verifies the result's exact request step
and packet-before state. When an exact steering rule wins, it also verifies
forced-rule provenance and any declared candidate, packet-after, disposition,
or action-contract override. The node plug-in remains the sole interpreter of
its forwarding object and action contracts.

`ForwardingSteeringRule` is an explicit user override for one exact step. It
may additionally require exact equality with `expected_before`; matching rules
use highest priority and an equal-priority tie is a contract error. The rule
may choose a candidate, replace the packet-after snapshot, or override the
disposition. `apply_forwarding_steering_rule()` marks the resulting transition
as `origin=user_forced`, records the actor and `forced_rule_id`, and
`evaluate_forwarding_packet_transition()` reports it as counterfactual.
The helper bounds its derived display label to the transition label limit; the
full user reason remains part of the steering-rule input and must be retained
by the coordinator when it is needed for review.
User-forced output is an exploration result: it never replaces observed
projection, becomes reachability ground truth, or silently changes a node
plug-in transition. A device's own policy steering remains
`origin=node_plugin` and must not claim a user `forced_rule_id`.

These packet types and helpers are an implemented public boundary. The bundled
demo exercises that boundary with generated route and packet evidence, but its
current scenario counts and materialization format are demo implementation
details documented in the [demo guide](../demo/README.md#generated-mock-dumps).
The demo does not provide production-style discovery/orchestration that
repeatedly invokes `resolve_forwarding_step()` across arbitrary installed
members.
Plug-in authors may implement and unit-test the hook, but must not assume every
server path executes it until that orchestration is explicitly advertised.

### Cross-node trace contribution contract

A node plug-in contributes only node-local forwarding semantics through its
projected IR. For a frozen `WorldBasis`, ingress VRF/destination, declared
status perspective, and hard candidate/depth limits, the core performs LPM and
traversal over that IR. The plug-in owns the explicit path-group mode, bounded
candidate membership, and ordered local resolution metadata that traversal
exposes; it does not return the final route answer. Each local step references
canonical resources and has a normalized phase, plug-in-owned
`resolution_text`, selected/degraded/unusable/unknown status semantics,
provenance, quality, evidence, and unknown fields. The string is plain display
text, not HTML, and may explain proprietary lookup, failover, label/SID/VLAN,
encapsulation, or adjacency decisions. The core must preserve it rather than
trying to derive an equivalent vendor explanation.

`NextHopGroup.mode` uses `PathGroupMode` (`single_active`, `all_active`, or
`unspecified`). Each `ForwardingMember` carries separate
`ForwardingMemberActivity` and `ForwardingMemberSelection` values, so an active
selection, a standby, an inactive candidate, and an unknown selection are not
collapsed into one boolean. Groups and members may attach bounded
`ResolutionContribution` records containing a normalized phase, plain plug-in
text, canonical resource/topology references, quality, and evidence. These
records explain node-local choices; they do not authorize a plug-in to traverse
another member or choose a final end-to-end branch.

Ingress-dependent candidate policy is also typed. A plug-in attaches
`ForwardingCandidateConstraint` values to the affected `ForwardingMember`.
For the v1 `EXCLUDE_EXACT_SCOPE` operation, each constraint declares:

- a stable `constraint_id`;
- one `ForwardingPolicyScope` whose `contract_id` and ordered typed
  `arguments` define the plug-in-owned equality domain;
- a `frozenset` of applicable traffic-class IDs, or an empty set for every
  traffic class; and
- bounded `ResolutionContribution` values explaining the device or protocol
  rule and its evidence.

The JSON transport for `ForwardingPolicyScope.arguments` is an ordered array of
`{"name": ..., "value": ...}` objects. A JSON mapping is rejected because map
iteration order is not part of the plug-in equality contract. Argument names
must be unique and typed values retain their exact scalar/container identity.

The core may compare only complete `ForwardingPolicyScope` values for equality.
It must not parse or normalize their arguments, infer prefix membership, or
attach meaning to a contract ID. The plug-in therefore owns such details as an
EVPN Ethernet Segment or split-horizon group, bridge domain/EVI, ESI-label and
DF behavior for known-unicast or BUM traffic, and BGP learned-from,
AS-path/originator/cluster-list, or site-of-origin policy. The core owns the
generic verdict. The caller also declares whether the observed ingress-scope
set is complete. An applicable exact ingress-scope match is `BLOCKED`, even
when other scopes are unknown. An applicable non-match is `PERMITTED` only
when the set is complete; an incomplete non-match is `UNKNOWN`. A known
non-applicable traffic class is `NOT_APPLICABLE`, and an omitted traffic class
needed to decide applicability is also `UNKNOWN`. `ForwardingPolicyDecision`
validates that matrix and preserves the candidate, constraint, traffic class,
ingress scopes, completeness, and plug-in explanation.

For multiple constraints, aggregate precedence is `BLOCKED` over `UNKNOWN`,
then `PERMITTED`, then `NOT_APPLICABLE`. A candidate with no constraints is
`PERMITTED`. `NOT_APPLICABLE` means that rule does not govern the supplied
traffic class; it is not a blocked path and does not by itself stop traversal.
A blocked candidate remains in the bounded trace as an intentional policy
exclusion; it is not silently removed or mislabeled as a failed physical link.
The protocol-neutral core entry points are
`evaluate_forwarding_constraint()` for one rule and
`evaluate_forwarding_policy()` for the aggregate candidate verdict. A plug-in
projects inputs to those functions; it must not manufacture its own core
verdict.

`FibEntry.presentations` and `TunnelAction.presentations` may carry bounded
`RoutePresentationDescriptor` values when the plug-in needs to relate service
intent or an encapsulation action to the graph. Each descriptor has a stable
opaque `presentation_id`; an explicit `principal`, `overlay`, or `annotation`
role; a `path`, `step`, `span`, or `resource` scope; and one safe core-rendered
style primitive (`path`, `band`, `badge`, or `callout`). Its topology references
are canonical `ResourceKey` values or declarative `TopologyMatchReference`
values. The coordinator resolves a match only when its advertised contract has
exact-token semantics; it never guesses from a prefix, label, VRF, VNI, VLAN,
SID, or protocol name. Optional anchor resources and bounded plug-in-owned facts
provide correlation and hover detail.

These descriptors are presentation sidecars, not forwarding edges. They cannot
change LPM, candidate selection, path ordering, reachability, or the physical
L1-L3 principal path. The plug-in decides whether a fact represents a VPN,
service overlay, label/SID action, VLAN attachment, or another proprietary
concept. The core validates identity and references, preserves time and
provenance from the owning forwarding record, and maps the declared style
through its own accessible theme. Plug-ins cannot supply CSS, HTML, layout
coordinates, or executable rendering behavior.

A trace-capability declaration may name node-local projections required by the
resolver in addition to the projection currently shown on the topology page.
The core may invoke those projections only for the same selected member,
plug-in set, and temporal basis; it exposes the auxiliary evidence context and
does not replace the user's topology context. This lets a control-path
alternative use control-state evidence without making it observed forwarding
ground truth.

Path-group mode is semantic output, not a UI guess:

- `single_active` identifies at most one selected primary and may expose ordered
  standby candidates. Standby means eligible after a failover predicate; it is
  not currently forwarding. If the selected primary is unknown, the plug-in
  returns alternatives with the uncertainty instead of choosing one.
- `all_active` identifies an explicit ECMP/multipath group and its concurrently
  eligible members, preserving weights and selection metadata when known.
  Duplicate rank or multiple viable next hops alone is insufficient.

New projections always declare the mode. The legacy route-executor v1
compatibility envelope may omit `multipath_mode` only when zero or one
candidate is selected; the coordinator then normalizes it to
`single_active`. An omission with multiple selected candidates is ambiguous
and fails validation rather than being interpreted as ECMP.

The plug-in stops at a local egress connector claim. It must not identify a
remote member, walk another node's state, align clocks, or assemble an
end-to-end path. Inter-node candidate matching belongs exclusively to the
selected federation/linker plug-in, which consumes bounded normalized boundary
claims and returns matched, ambiguous, unresolved, or conflicting candidates
with evidence. The core owns the immutable context, per-member temporal
resolution, query budgets, branch expansion, loop detection, stable path/step
ordering, cross-perspective comparison, coverage, and navigation links.
When a packet state crosses a matched boundary, the linker may preserve an
exact compatible packet/scope contract or explicitly map a contract it owns.
It does not add, remove, reorder, or reinterpret packet layers as an implicit
forwarding action. If it cannot preserve the contract, the receiving packet or
scope evidence is incomplete rather than guessed.

Traffic endpoint identity and traversal start are different concepts. A
bidirectional trace keeps one immutable source/destination flow pair while the
forward `ingress` or `trace_start` names only the member/resource where
observation begins. A transit start does not make that member the packet source.
Unless the request supplies an explicit return start, the reverse traversal
starts from a time-valid attachment of the traffic destination and targets an
exact attachment of the traffic source. It is never required to pass through or
terminate at the forward start.
For a bidirectional endpoint verdict, an explicit return start must resolve to
an available destination attachment. A plug-in may expose an arbitrary
mid-return observation as a single-direction diagnostic, but core must not
treat that suffix as proof that the destination can reach the source.

A compatibility executor whose scenario is fixed to one declared endpoint pair
may accept that same pair in either order. When the caller reverses the pair,
the coordinator uses the executor's opposite directional candidate and
per-visit decision declarations while preserving the caller-facing
`direction`. The counterpart request reverses the caller's flow, not the
executor's original labels. A fixed scenario with a multi-attachment
destination cannot reverse safely without an explicit source-attachment
contract and is rejected rather than selecting one attachment.

A node plug-in owns its normalized endpoint attachment declarations and the
local, perspective-specific classification that a selected forwarding action
delivers to or originates from one of those attachments. That classification
must use canonical resource or typed declarative-match references, validity,
quality, provenance, and evidence. It must not be hidden in
`resolution_text`, inferred from a display prefix, or expanded into remote
member knowledge. A federation/linker plug-in owns bounded cross-member
attachment and boundary matching. Core preserves the immutable flow, swaps
directional goals, selects or resolves traversal seeds, exact-matches a
plug-in-declared terminal to the requested endpoint, aggregates multipath
coverage, and produces the bidirectional endpoint-reachability verdict.
Every plug-in-selected active branch participates in that aggregate. Mixed
success/failure is `partial_active_reachability`; incomplete attachment or
terminal evidence is unknown. Neither case is promoted to fully reachable.
The protocol-neutral `evaluate_endpoint_reachability_pair()` helper performs
that final classification only after exact typed directional terminal results
are available; it does not parse endpoint values or manufacture attachment
evidence.

`path_relation` (`symmetric`, `asymmetric`, or `not_comparable`) describes
node-sequence shape only. Core may compare sequences when both directions cover
the same endpoint-to-endpoint span. It must return `not_comparable`
when, for example, the forward trace starts at a transit observation point.
It must also return `not_comparable` with
`reverse_endpoint_start_unknown` when the caller has not proved that the
return trace starts at the destination endpoint. That uncertainty does not
erase an independently established endpoint-reachability result.
Path relation never determines consistency: forward must reach the traffic
destination and reverse must reach the traffic source. A complete path that
only reaches the forward start fails the reverse endpoint goal.

Every route/coverage record declares its routing context, including the VRF or
equivalent plug-in-owned scope, explicitly. The core does not invent a
`default` VRF, parse a prefix to manufacture endpoint aliases, or derive
attachment availability from display text. Plug-ins declare aliases and
time-valid endpoint attachments. Attachments may remain visible as
`available`, `unavailable`, or `withdrawn`; only an available attachment may
terminate a successful endpoint trace.

For loop detection, a node plug-in canonicalizes the typed local context that
it already owns; core records it as `ForwardingTraversalStateKey`. The key
contains member, `StatusPerspectiveRef`, forwarding object and domain, ingress
resource, typed lookup and packet contexts, the active
`ForwardingPolicyScope` set, and `policy_scopes_complete`. Core detects a loop
only when the complete frozen key repeats and returns a
`ForwardingCycleReport` with the first index, repeated
index, and closed key sequence. A repeated member name or router ID alone is
not a cycle: decapsulation, a service-chain hairpin, or another lookup/packet
context may legitimately revisit the same device. Plug-ins must not hide
context in `resolution_text` merely to influence loop identity, and they must
not declare a cycle themselves. Core exposes `detect_forwarding_cycle()` for an
exact-repeat check and `evaluate_forwarding_traversal()` when independent hop
and recursion budgets must also be classified. Exact repeats are checked before
budget exhaustion at the same step, so a proven loop is not mislabeled as a
limit. A proven repeat is terminal: the core truncates the executable path at
the closing state and cannot subsequently classify that branch as resolved or
target-reaching. Candidate count, segments per path, hop count, and recursion
depth are core-enforced limits; plug-in-supplied counters are consistency
evidence and cannot expand those budgets.

For the compatibility candidate envelope, each opaque traversal declaration
also carries `identity_complete`. It defaults to false and may be true only
when the opaque key covers every cycle-relevant component above. Core publishes
that value as `canonical_identity_complete`. Equal incomplete keys do not mark
an occurrence as repeated and cannot create a `cycle` result; independent hop
and recursion budgets still apply.

Status perspectives are resolved independently. A plug-in must not borrow a
control-plane value to fill an unknown hardware value, and it must retain
different local next hop, egress interface, destination, or encapsulation
results for comparison. An explicit trace policy can name one advertised
perspective as reachability ground truth, but neither a plug-in default nor an
observed role implies that choice.

Under strict completeness the core stops a branch at an unknown required local
status or boundary. Under best-effort it may explore bounded candidates, but
the plug-in/linker provenance, observation basis, assumptions, quality, and
unknowns remain attached to every resulting step. Neither the core nor a later
plug-in may promote a continuous best-effort branch into ground-truth topology
or exact reachability. Conformance fixtures must cover single-active failover,
all-active ECMP, an indeterminate primary, per-layer path disagreement,
ambiguous/unresolved federation boundaries, and strict versus best-effort
coverage. They must also cover a transit forward start distinct from the
traffic source, a successful return path that bypasses that start, a return path
that reaches the start but not the source endpoint, and incomplete or
multi-attachment endpoint evidence.

## 8. Plugin conformance suite

Every platform/version plugin should provide a redistributable synthetic corpus
and run these tests:

Start with the generic author check:

```text
router-dump-plugin-validate ENTRY_POINT --artifact REPRESENTATIVE_PATH --node-hint NODE --metadata platform=PLATFORM --metadata software_version=VERSION
```

This is a structural smoke test, not a substitute for the following
device-semantic cases.

The command's closed prose remains exact, while every plug-in/loader-owned
fragment is projected through the shared bounded public-text policy before it
is printed. Oversized text, probable host or traversal paths, unsafe invisible
text, and ambiguous display characters cannot leak through validator stdout;
plug-ins MUST use structured diagnostics rather than parse exception prose.
The validator MUST resolve the installed object's `manifest` and each relevant
hook descriptor at most once per run, and MUST use static class inspection when
it determines whether an `AnalyzerPluginBase` hook was overridden. An ordinary
descriptor exception produces a bounded failed report. A different ordinary
exception escaping the validation implementation is contained by the command's
final boundary and exits with status 2 without a traceback. `KeyboardInterrupt`,
`SystemExit`, and `GeneratorExit` remain process-control exceptions and MUST NOT
be converted into validation results. This includes nonstandard
`BaseException` subclasses raised by manifest or hook descriptors, `describe()`,
`probe()`, `locate_inputs()`, or the validator's loader: they MUST be contained
without a traceback or untrusted exception text unless they are one of those
three process controls.

The host applies the same rule to installed loading, ingestion discovery and
parser streams, runtime/session descriptors, context entry/exit, normalized
data providers, temporal readers, and route packet-transition callbacks.
Descriptors are snapshotted once per operation/session. Lazy iteration and
`close()` are inside the boundary, and a failing context cleanup cannot replace
an exception already raised by the core-owned body.

When the default `router-dump-analyzer` CLI hosts the application, core MUST
enter the real application lifespan before Uvicorn starts and MUST disable
Uvicorn's duplicate lifespan driver for that server run. Every ordinary
plug-in failure during runtime open, context entry, or lazy discovery MUST
exit with status 1 and exactly one bounded, path-free CLI error line. It MUST
emit no traceback and MUST NOT convert `KeyboardInterrupt`, `SystemExit`, or
`GeneratorExit` into a public failure.

### Probe and input discovery

- Exact version, adjacent version, ambiguous version, and missing manifest.
- A top-level tar or ZIP and its unpacked directory form produce equivalent
  inventory. Add nested-codec equivalence only when the deployment implements
  and advertises that future pipeline.
- Renamed internal root with plugin-declared locator still works.
- Required input missing produces a structured diagnostic.

### Parser robustness

- Empty, truncated, malformed, wrong encoding, very long line, repeated section.
- Unknown fields are retained or diagnosed according to policy.
- 100K+ records stream within memory limit.
- Plug-ins emit compact state deltas; the core lazily reconstructs intervals only for queried resources and preserves failed-event no-mutation semantics.
- When the deployment supplies a core `TraceDecoder`, CTF 2 passing and failing
  decoder corpus cases. Without one, selecting CTF must fail closed rather than
  implying built-in decoding.

### Optional capability caller

- Invoke every advertised optional hook through
  `PluginCapabilityExecutor`, not by calling the plug-in directly.
- Undeclared capabilities fail before invocation; malformed, undeclared,
  dangling, non-recoverable, and over-limit outputs fail without a partial
  result.
- Bounded world reads and output iterators stop at their configured limits and
  close the underlying iterators; recoverable diagnostics remain in their typed
  result envelope.

### Reducers

- `apply()` changes every linked resource the real callback changes.
- `revert(apply(world)) == world` for declared exact/invertible events.
- Partial/non-invertible events return unknown instead of a fabricated inverse.
- `create`, `add`, and `insert` all open lifecycle existence; delete/recreate
  yields separate incarnations.
- Relationship changes create correct half-open intervals.
- Equal-timestamp replay is deterministic in
  `(timestamp, source_sequence, stable event/change ID)` order.
- Adjacent topology-change windows use `[start_ns,end_ns)` and return a
  boundary event only in the later window.

Property-based tests with Hypothesis are well suited to reducer round trips and
random event sequences.

### Clocks and correlation

- Clock offset, drift, wrap, missing anchor, overlapping uncertainty.
- Absolute strict queries resolve every node independently; an unaligned node is
  unknown rather than compared by raw timestamp.
- Relative queries use the selected perspective/projection watermark, not a
  global event maximum or another layer's watermark.
- A complete local-only scoped watermark resolves a relative query without a
  wall-clock transform; a missing declaration uses only the labeled legacy
  capture-lag path.
- A clock uncertainty range that crosses a resource or relationship transition
  returns ambiguous alternatives rather than one arbitrarily chosen state.
- One-to-many and many-to-one cross-layer correlation.
- Same display name with distinct typed keys does not merge.
- Weak correlation remains low-confidence/ambiguous.
- Budget exhaustion and high fan-out remain bounded and are reported as partial,
  never exact.

### Consistency and forwarding

- PASS, FAIL, and UNKNOWN for every rule.
- Callback success with hardware mismatch is FAIL/UNKNOWN as specified, not PASS.
- LPM, ECMP, failover, unresolved neighbor, recursive next hop, and cycle limit.
- Exact recursive-state cycles and cross-node forwarding loops retain their
  closing occurrence and terminate before a hop/recursion budget result.
- A same-node revisit with a different lookup, packet, ingress, or policy-scope
  context does not produce a false cycle; hop exhaustion remains a distinct
  bounded result.
- Repeated opaque traversal keys with `identity_complete=false` do not prove a
  cycle.
- Packet layers remain outermost-to-innermost, complete transitions preserve
  exact before/after continuity, incomplete continuity remains unknown, and
  the independent packet-step budget is enforced.
- Packet-state conformance covers an MPLS/SR-MPLS push/swap/pop or PHP-shaped
  transition, SRv6 or another ordered wrapper, decapsulation with an inner
  layer retained, and a legitimate same-node revisit after packet-context
  change. Protocol vocabulary and expected layer changes come from the fixture
  plug-in, not core.
- MTU tests cover `fits`, `exceeds`, missing/incomplete evidence, and unequal
  basis contracts. A plug-in-declared drop or punt is tested separately from
  core's arithmetic result.
- User steering exact-matches the target step and optional packet snapshot,
  rejects an equal-priority ambiguity, retains actor/rule provenance, and is
  reported as counterfactual rather than observed reachability.
- A trace beginning at a transit member preserves a different immutable traffic
  source. Its successful return reaches the source endpoint without being
  required to visit the forward start, and its path relation is
  `not_comparable`.
- Reversing a fixed endpoint pair uses the opposite executor direction while
  retaining the caller-facing direction; an ambiguous multi-attachment
  reversal fails closed.
- Omitted legacy `multipath_mode` is accepted only for an unambiguous
  zero-or-one-selected-path executor; multiple selected paths require
  `all_active`.
- Reaching the forward start without reaching the exact source endpoint remains
  one-way or unreachable. Unknown, ambiguous, withdrawn, and multihomed
  endpoint attachments retain bounded alternatives and coverage rather than a
  guessed terminal.
- Ingress-dependent candidate constraints cover EVPN known-unicast and BUM
  split horizon, BGP control-policy rejection, non-applicable traffic, and
  unknown traffic or incomplete scope evidence without deleting rejected
  candidates. A known-empty complete scope set remains distinct from an
  incomplete set.
- Every route result has a deterministic explanation tree and evidence links.
- Applying forwarding deltas yields the same records as a clean full projection.
- Switching status perspective retains topology identity while changing only
  the selected perspective's status; missing status remains explicit unknown.
- Historical topology snapshots and change streams respect resource, edge, and
  endpoint validity intervals for both absolute and relative selectors.
- Topology hooks reject undeclared projection/perspective pairs, duplicate or
  over-budget records, invalid exact/match endpoint unions, and dangling
  canonical resource keys.
- Conflicting paired link types return sorted claims plus deterministic
  `unknown`/`plugin_link_type_mismatch`, never an order-dependent winner.
- Declarative match references round-trip without core interpretation and retain
  all plugin-resolved candidates, source-resource keys, and evidence.

### Core ingestion runtime

Every ordinary parser plug-in additionally proves:

- core artifact inventory rejects unsafe names, links, special members,
  collisions, and each configured count/depth/byte/ratio overflow;
- the plug-in can consume only its selected logical IDs through read-only
  streams or session-private materializations;
- capability-gated dispatch, schema references, evidence membership, exact
  integer/boolean fields, time bounds, and output types are validated;
- cycles, non-finite values, oversized atoms/containers/streams, and
  non-recoverable diagnostics fail without partial publication;
- repeated ingestion of identical content has stable revision/resource/source
  identity; and
- the core-owned runtime-v2 session serves its normalized `/v1/workspace` while
  unsupported temporal/topology/route providers remain `None`.

The same representative fixture SHOULD also pass once through
`router-dump-ingest` with the plug-in as the explicit allowlist. That smoke
proves queue-time probe/discovery/parser determinism and immutable catalog
publication; it does not require the plug-in to implement or inspect any
control-plane object. Core's own durable contract suites cover tenant scope,
idempotency, optimistic versions, leases/recovery, sessions/snapshots,
annotations, reports, and HTTP translation.

The repository example owns a compact heterogeneous corpus:

```text
python -X utf8 -m rsl_demo_generator --write-ingestion-conformance-corpus path/to/runtime-v2-ingestion-conformance.tgz
python -X utf8 -m rsl_demo_generator --verify-ingestion-conformance-corpus path/to/runtime-v2-ingestion-conformance.tgz
python -m unittest tests.test_artifact_core tests.test_ingestion tests.test_capability_executor -v
python -m unittest discover -s state-dump-generator/tests -p "test_runtime_v2_vectors.py" -v
```

Its embedded and standalone semantic vectors label each case by current
execution stage. The current status slice is executable through the example
parser and coordinator. Text, CTF, malformed, unsupported, typed-key,
relationship, and uncertainty cases remain explicit without claiming a
built-in CTF decoder or an unimplemented provider.

### Compatibility runtime adapter

When a precomputed-fixture plug-in exposes `plugin.runtime` v1, conformance
additionally proves:

- the capability ID and every structural session member validate;
- invalid or unsupported input fails before serving requests;
- required providers work and unsupported optional providers are `None`;
- the context releases stores, indexes, and caches exactly once;
- the runtime and demo distribution import no web framework or core frontend;
  and
- the core CLI can load the same instance by installed entry-point name and,
  for source development, by direct module target.

The repository's `samples/` directory is a core smoke-test corpus. Real plugins
need richer product-shaped synthetic generators, especially failure and clock-skew cases.
