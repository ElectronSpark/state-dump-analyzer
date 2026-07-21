# Plugin contract and lifecycle

The core owns safety, lifecycle, canonical storage, temporal semantics, API, and
UI. A plugin owns only facts that vary by software/platform version.

The executable reference types are in
`src/router_dump_analyzer/plugin_api.py`.

## 1. Packaging and discovery

Each plugin is an independently versioned Python distribution with an entry
point. A minimal declaration looks like:

```toml
[project.entry-points."router_dump_analyzer.plugins"]
synthetic_router_2025 = "vendor_router_plugin:plugin"
```

The loaded object implements `AnalyzerPlugin` and exposes a `PluginManifest`.
The server records distribution name/version/hash, manifest, plugin API version,
configuration hash, and decoder version in the analysis revision.

Do not use filename-based module discovery or import Python files found in the
dump. The deployment owns an allowlist of installed plugin distributions.

## 2. Capability boundary

| Capability | Plugin responsibility | Core responsibility |
|---|---|---|
| Probe | Detect platform/version from safe inventory metadata and return a structured probe report. | Run every allowed probe with limits and resolve ambiguity explicitly. |
| Locate | Select logical artifacts/parser roles or emit structured missing-input diagnostics. | Materialize only those artifacts into a private workspace. |
| Status parse | Yield resource and relationship observations, scoped completeness markers, and precise evidence locators. | Batch validation, identity assignment, storage, diagnostics. |
| Trace parse | Map dependency-free core CTF records or raw text into domain events. | Own `bt2`, normalize native messages, retain raw time/source order, enforce quotas, and persist decoder diagnostics. |
| Source-record presentation | Declare source-type labels/colors and optional regex-lane presets; link decoded records to domain events when normalization succeeds. | Retain matched and unmatched timestamped records, assign stable IDs, validate regexes, page/query records, and implement timeline/log navigation. |
| Reduce | Convert one event into all direct/derived state and edge changes. | Deterministic ordering, interval materialization, checkpointing. |
| Revert | Invert an event when information permits. | Mark non-invertible state unknown and measure reconstruction coverage. |
| Correlate | Query a bounded indexed reader and emit cross-layer edges, event causal links, and clock anchors. | Clamp windows/budgets, persist evidence/quality, and reject invalid references. |
| Check | Return PASS/FAIL/UNKNOWN findings. | Execute rules at selected time/revision and aggregate dashboard results. |
| Forwarding | Project bootstrap or bounded `ChangeSet` deltas into a negotiated typed forwarding IR. | Validate/version/store deltas; own LPM, recursive resolution, cycle/limit handling, and explanation API. |

Plugins never receive application database credentials and never mutate core
tables. They return records through a validated IPC/batch channel.

`InputSpec.artifact_ids` may name several files that form one logical input. This
is required for CTF, where `metadata`, data streams, and optional index files must
be handed to Babeltrace as one private directory tree. A single materialized file
path is not a sufficient CTF contract.

The core invokes its `TraceDecoder`, consumes native decoder diagnostics, and
passes the plugin only an `Iterable[CtfMessage]`. That union represents event,
stream/packet/activity boundary, discarded-event, and discarded-packet messages
with stable ordinals, trace/stream identity, clocks, normalized payload/context,
and evidence. A native `bt2` object or iterator is never plugin input. CTF roles
use `parse_ctf(spec, messages)`; text-log roles use the separate
`parse_text_trace(reader, spec)` hook and only the quota-enforced reader.
Mapped `DomainEvent` records retain the core `SourceRecordRef` (source, trace,
stream, packet, and message ordinal); a plugin must not hide source identity only
inside a human locator.

The core may retain any timestamped decoder input as a generic `SourceRecord`,
including CTF messages, syslog lines, agent callbacks, and records decoded from
status text. A plug-in supplies the `source_type`, decoded record name/message,
attributes, and an optional `matched_event_uid`. No match is also a first-class
result: unmatched records remain queryable and can appear on dedicated timeline
lanes. The core owns stable source-record IDs, timestamp normalization, storage,
pagination, range membership, and source-to-domain links.

`PluginSchema.source_record_types` contains labels, descriptions, and safe
colors. `PluginSchema.record_lane_presets` may provide useful source filters,
such as unmatched CTF records or Ethernet Segment messages. These presets are
declarative regex/source-type filters only. The browser may add or remove custom
rules, but the core applies the same pattern-length, feature, lane-count,
haystack, and result-size limits to plug-in presets and user-created rules.
Plug-ins never provide executable browser matching code.

## 3. Required semantics

### Resource keys

- Keys are typed and ordered, not colon-joined display strings.
- Boolean key parts are forbidden because Python otherwise conflates `True` and
  integer `1`; encode such a discriminator as an explicitly tagged string/int.
- The same logical key after a confirmed delete/recreate may be a new incarnation.
- Unknown references are emitted as keys and become placeholders; they are not dropped.
- Canonicalization rules are part of the plugin's compatibility contract.

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

Every world exposes an observed-capture-vector or reconstructed-time basis.
Resource views retain validity/capture ranges and evidence, so findings and
forwarding projection can preserve the actual observation anchors.

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
raw states into core semantic fields such as admin/oper state, severity,
provenance, and quality. The web theme maps those semantic values to accessible
colors; plugins must not emit CSS or assume a particular color palette.

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

The core validates and serializes these declarations, calculates their values
from the generic point-in-time resource query, escapes every value, and renders
the common controls. Plugins do not provide markup, scripts, styles, URLs, query
code, or callbacks. This keeps resource semantics in the plugin without making a
plugin part of the browser trust boundary.

The browser presents all descriptors in an index and opens the
`default_open` modules at the end of the page. Open/closed, expanded/collapsed,
and user-defined order are local presentation state. Moving or collapsing a
module never changes the plugin schema or the analysis revision; a reset restores
the descriptor defaults. A non-collapsible module must be expanded by default.

### Determinism

For identical artifacts, configuration, and plugin build, output must be stable:

- Stable event UID derived from source identity and ordinal/locator.
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
timestamps as signed `int64`; public JSON APIs encode nanoseconds and other
unsafe 64-bit integers as decimal strings. This conversion is owned by the core,
not reimplemented differently by each plugin.

## 5. Version selection

Probe results contain confidence and reasons, but confidence is not permission to
guess. The core policy should be:

1. One exact platform/version match: select it.
2. Multiple exact matches: fail as ambiguous unless configuration resolves it.
3. Only compatible-range matches: show candidates and require operator choice.
4. No match: keep the import at `PROBED` with diagnostics.

Persist the candidate-set/inventory hash with the exact selected plugin ID,
version, distribution hash, and configuration hash. Selection and resume calls
are idempotent; a stale or concurrent choice is rejected. Resuming validates the
durable stage and does not reuse partial output created by another plugin build.

Composition is useful: a family plugin may provide common archive/status parsing,
while a release adapter overrides resource mappings or reducers. The final bundle
still has one recorded, reproducible manifest/hash.

## 6. Process and security model

Plugin execution is trusted code in a hostile-input boundary, so isolate it:

- Disposable Linux process/container per job or bounded job group.
- Read-only plugin image and read-only artifact handles.
- Private scratch directory with byte/inode quota.
- No network, secrets, database socket, or host paths.
- CPU, memory, file, child-process, output, and wall-time limits.
- Native Babeltrace failures terminate only the worker.
- Coordinator validates all output and performs persistence.

`ArtifactReader.materialize_private_path()` supports a single native input;
`materialize_private_tree()` reconstructs a selected logical subtree for
Babeltrace and other multi-file readers. Neither returns an application or
host-global path.

Core materialization explicitly applies Python 3.12's `filter="data"` at every
tar layer and then a stricter policy: regular files only; normalized relative
paths; no links/devices/special members/collisions; and streaming quotas for
members, depth, bytes, and ratios. Plugins may not open or extract an archive on
their own; they consume only validated artifact handles/private trees.

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

`project_forwarding(ir_version, changes=None, world)` is a deterministic
streaming bootstrap. For later calls, `changes` is one bounded change set and the plugin yields only
affected upserts/deletes. Batches follow the same backpressure and size rules as
other outputs. Conformance compares a delta-maintained projection with a clean
bootstrap, checks removal of stale objects, and rejects invalid references or IR
versions.

## 8. Plugin conformance suite

Every platform/version plugin should provide a redistributable synthetic corpus
and run these tests:

### Probe and input discovery

- Exact version, adjacent version, ambiguous version, and missing manifest.
- Nested archives and unpacked directory form produce equivalent inventory.
- Renamed internal root with plugin-declared locator still works.
- Required input missing produces a structured diagnostic.

### Parser robustness

- Empty, truncated, malformed, wrong encoding, very long line, repeated section.
- Unknown fields are retained or diagnosed according to policy.
- 100K+ records stream within memory limit.
- Plug-ins emit compact state deltas; the core lazily reconstructs intervals only for queried resources and preserves failed-event no-mutation semantics.
- CTF 2 passing and failing Babeltrace corpus cases.

### Reducers

- `apply()` changes every linked resource the real callback changes.
- `revert(apply(world)) == world` for declared exact/invertible events.
- Partial/non-invertible events return unknown instead of a fabricated inverse.
- Delete/recreate yields separate incarnations.
- Relationship changes create correct half-open intervals.

Property-based tests with Hypothesis are well suited to reducer round trips and
random event sequences.

### Clocks and correlation

- Clock offset, drift, wrap, missing anchor, overlapping uncertainty.
- One-to-many and many-to-one cross-layer correlation.
- Same display name with distinct typed keys does not merge.
- Weak correlation remains low-confidence/ambiguous.
- Budget exhaustion and high fan-out remain bounded and are reported as partial,
  never exact.

### Consistency and forwarding

- PASS, FAIL, and UNKNOWN for every rule.
- Callback success with hardware mismatch is FAIL/UNKNOWN as specified, not PASS.
- LPM, ECMP, failover, unresolved neighbor, recursive next hop, and cycle limit.
- Every route result has a deterministic explanation tree and evidence links.
- Applying forwarding deltas yields the same records as a clean full projection.

The repository's `samples/` directory is a core smoke-test corpus. Real plugins
need richer product-shaped synthetic generators, especially failure and clock-skew cases.
