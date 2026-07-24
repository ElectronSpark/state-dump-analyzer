# Architecture and library decisions

Status: proposed baseline, researched 2026-07-19
Runtime: Python 3.12 on Linux for the server and analysis workers

## 1. Executive decision

Start as a modular monolith with isolated workers, not as microservices and not
as a graph-database product.

```mermaid
flowchart LR
    U["Dump upload or server-side folder"] --> A["Safe artifact inventory"]
    A --> P["Plugin probe and explicit selection"]
    P --> W["Isolated analysis worker"]
    W --> CTF["Babeltrace 2.1 CTF decoder"]
    W --> S["Status and text parsers"]
    CTF --> N["Canonical records"]
    S --> N
    N --> T["Clock alignment and temporal reconstruction"]
    T --> V["Validation and consistency rules"]
    V --> R["Immutable published analysis revision"]
    R --> DB["PostgreSQL serving tables"]
    R --> OBJ["Artifact/object storage"]
    DB --> API["FastAPI"]
    API --> UI["Timeline, dependency graph, dashboard"]
    API --> EXT["Other tools and future topology analyzer"]
```

The default serving store is PostgreSQL because this is a concurrent server,
the data volume in the brief is moderate, and temporal interval queries fit its
`int8range`, GiST, JSONB, and `inet` support. Keep original and large extracted
artifacts in content-addressed filesystem or S3-compatible storage.

If a revision grows from hundreds of thousands into tens or hundreds of
millions of records, add immutable Parquet fact datasets, publish them through a
revision manifest, and use DuckDB for offline/worker analytics. Do not make one
mutable DuckDB file a multi-process server database.

## 2. Correctness constraints that shape the product

### 2.1 Exact reverse history is not guaranteed

A latest snapshot and a sequence of received updates do not uniquely determine
past state unless every change is invertible.

- `property = 5` does not reveal the prior property value.
- A delete may omit the deleted object.
- A callback returning success does not prove all derived hardware writes completed.
- Internal mutations may have no corresponding gRPC message.
- A relationship may change without the old target appearing in the log.
- Status files from different layers may have been collected at different times.

Every plugin declares a reconstruction **default** of `exact`, `best_effort`, or
`unsupported`, but that is never promoted to a blanket guarantee. Every semantic
output carries orthogonal provenance (`observed`, `event_derived`,
`reconstructed`, `correlated`, or `plugin_default`) and quality (`exact`,
`best_effort`, `ambiguous`, or `unknown`). Field-level quality and explicit
unknown reasons override the record-level summary. Absence from a partial update
is not interpreted as deletion.

Prefer forward replay from the earliest coherent checkpoint or applicable
earlier observation anchors. Reverse replay from later observations is permitted
only through a plugin-supplied `revert()` reducer.
Here, "snapshot" means a collection of individual observation constraints, not
one simultaneous world: every resource, field group, and observed relationship
retains its own capture interval. A dump-wide timestamp is merely a collection
hint unless the capture mechanism proves simultaneity.

### 2.2 Preserve four different facts

Do not collapse these into one generic event table or one graph edge:

| Concept | Meaning |
|---|---|
| Observation | A value read from a status snapshot, with its capture-time range. |
| Event | Something recorded in a trace or debug log. |
| Mutation | A state/relationship change inferred from an event by a plugin. |
| Causal link | Evidence that events in different layers correspond or caused one another. |

Structural ownership, runtime dependency, reference, cross-layer correspondence,
and event causality are separate relation types with separate semantics.

### 2.3 Time is evidence, not just a timestamp

Keep all of the following:

- Raw timestamp and its clock domain.
- Stream and source sequence/ordinal.
- Normalized nanoseconds, when a transform is known.
- Uncertainty interval and clock-transform evidence.
- Deterministic ingestion order for reproducibility.

When uncertainty windows overlap, a strict cross-container order is not proven.
The system may use a deterministic linearization for stable output, but affected
states and causal links must be marked ambiguous. Use signed 64-bit nanoseconds;
serialize them as decimal strings in JSON because JavaScript numbers cannot
represent them exactly.

Absolute external queries name their clock domain. The core maps that instant
into every selected node independently through recorded transform segments and
returns the resulting local/absolute uncertainty ranges. Equal raw values from
different node clocks are never evidence of simultaneity. Under strict policy,
a missing transform is `clock_unaligned`, and an uncertainty range crossing a
state transition yields ambiguous alternatives rather than an arbitrary side.

Relative queries are anchored to a scoped completeness watermark, not the
greatest timestamp in a dump. The scope includes node, selected status
perspective, and optional topology projection. An offset of zero means the
latest completely reconstructed status for that exact scope; negative offsets
select its past. Resolving this independently across nodes produces a capture
vector, not necessarily one wall-clock instant.

Events without a usable timestamp remain in an **unplaced events** collection
with their source ordinal. They can be reached from resource history and source
context, but must not be assigned a fabricated point on the global timeline.

## 3. Analysis revisions and ingestion lifecycle

Every import produces an immutable `analysis_revision` identified by:

- Input content hash and node/case identity.
- Core schema/API version.
- Plugin IDs, versions, package hashes, and configuration hash.
- Babeltrace decoder version and supported CTF/MIP version.
- Clock alignment configuration.

Reprocessing after a plugin upgrade creates a new revision. Published rows are
never reinterpreted in place. A small transaction changes the case's published
revision pointer only after validation succeeds.

Recommended job state machine (an exact configured match may pass directly from
`PROBED` to `SELECTED`):

```text
RECEIVED -> INVENTORIED -> PROBED
PROBED -> AWAITING_SELECTION -> SELECTED
PROBED -----------------------> SELECTED  (exact configured match)
SELECTED -> PARSING -> NORMALIZING -> ALIGNING -> RECONSTRUCTING
         -> VALIDATING -> PUBLISHED
```

Failures stay attached to an unpublished revision with structured diagnostics.
Send only job IDs and artifact references through the queue, never dump bytes.

### Stage details

1. **Receive**: spool the upload to quota-controlled storage and compute SHA-256.
2. **Inventory**: walk archives without blindly extracting them; record logical
   path, parent archive, type, sizes, and content hash where practical.
   The core detects each compression/archive layer from observed content,
   applies its allowlist and quotas, and records the actual outer-to-inner codec
   chain. A plug-in may provide declarative artifact locators and role hints
   after safe inventory, but it never chooses a decoder or authorizes
   extraction. For example, `.zst.gz` is peeled as an outer gzip stream followed
   by the observed Zstandard stream; the suffix is not trusted as evidence.
3. **Probe/select**: run allowlisted plugin probes. If two plugins are plausible,
   persist candidates and pause for an explicit choice; never silently select the
   nearest software version. Record the chosen plugin ID/version/package hash and
   probe-set hash before an idempotent resume.
4. **Materialize selected inputs**: extract only plugin-selected artifacts into a
   private worker directory. CTF filesystem traces need a real directory containing
   `metadata` and stream files.
5. **Parse**: stream snapshot observations and trace events in bounded batches.
6. **Normalize/correlate**: assign typed resource identities, mutations,
   relationships, causal links, and clock anchors.
7. **Reconstruct**: create state and relationship validity intervals.
8. **Validate**: replay in the opposite direction where possible, compare terminal
   reconstructed state to observations, execute tri-state consistency rules, and
   record coverage.
9. **Publish**: bulk-load/index serving tables and atomically expose the revision.

## 4. Plugin architecture

Discover plugin bundles through Python entry points under
`router_dump_analyzer.plugins`. The reference protocol is in
`src/router_dump_analyzer/plugin_api.py`; operational rules are in
`docs/plugin-contract.md`. First-time authors use
`docs/plugin-author-quickstart.md` and the installable
`examples/minimal_plugin/` before consulting the full normative contract.

### Three-owner rule

- **Core** owns trust boundaries and mechanics: safe artifact materialization,
  canonical envelopes and identity, clock transforms, interval reconstruction,
  persistence, budgets, APIs, orchestration, and generic rendering.
- **Node/device plug-ins** own platform-, release-, layer-, and protocol-specific
  meaning: parsing, typed keys, status normalization, mutations, local
  correlations, forwarding/topology projections, and declarative presentation.
- **Federation/linker plug-ins** own cross-node inference over bounded normalized
  claims: peer/domain matching, corroboration, ambiguity policy, and inter-node
  link semantics. They do not read raw node artifacts or replace node-local
  state.

The core must not branch on plug-in kind, relation, source-type, source-group,
or key-field names. The detailed audit and migration ledger is in
`docs/core-plugin-boundary-audit-2026-07-22.md`.

A plugin bundle supplies:

- Platform/version probe and input locators.
- Status parsers, text-log parsers, and domain mappers for core-decoded CTF records.
- Typed resource keys and display metadata.
- Forward and reverse reducers.
- Dynamic relationship and cross-layer correlation rules.
- Raw clock domains, anchors, and device-specific anchor interpretation; the
  core fits and validates transforms and resolves temporal selectors.
- Consistency checks.
- Projection into a canonical forwarding model.
- Sensitive-field declarations for structured resource properties. The core
  owns public source-record projections, authorization, and raw-context access;
  the current protocol does not expose a plug-in source-context policy hook.

The module-level entry-point target is an instance. Every plug-in has the
required `describe`, `probe`, and `locate_inputs` hooks; standard
`PluginCapability` values activate optional hooks. `InputSpec.parser_kind`
selects status, CTF, or text-trace dispatch without interpreting the plug-in's
opaque `role` or `parser_id`. `AnalyzerPluginBase` gives authors safe no-ops for
undeclared capabilities and rejects declared behavior that was not implemented.
Parser hooks emit `SourceRecordEmission` before the core assigns stable
`SourceRecord` identity. The generic `router-dump-plugin-validate` command
checks this cold-start contract before product-specific conformance runs.

Plugins emit iterators/batches; they do not write the database. For production,
use Arrow `RecordBatch` messages between the plugin worker and coordinator so
100K+ records do not become millions of Python ORM objects. Validate every batch
against the core schema at the process boundary.

A Python import is not a sandbox. Execute plugins and the native Babeltrace
decoder in disposable, resource-limited Linux processes/containers without
network access or application database credentials.

The worker/core owns `bt2` iterator lifecycle and converts every native message
into a dependency-free record: event; stream, packet, or activity boundary; or
discarded-event/packet notice, with trace/stream identity, stable message
ordinal, raw/default-clock time, payload/context, and source evidence. Native
`bt2` objects never cross the plugin call boundary. The core-assigned source
identity remains a typed field on the mapped domain event. The plugin only maps
those normalized records to domain events; this keeps decoder upgrades and
native failures inside one controlled boundary.

All input-dependent plugin methods can emit structured diagnostics; the static
`describe()` schema hook is validated or fails plugin loading. Correlation receives a
bounded, indexed `CorrelationReader` rather than the whole event list; it streams
candidates by time window, layer, event type, and subject, and can request a
read-only world at a time. World scans and relationship scans are iterators with
coordinator-enforced budgets, so checks and projections do not require a 100K+
object list in memory.

## 5. Canonical domain model

### 5.1 Resource identity

Each resource has:

- A stable opaque external ID derived from a canonical typed key.
- A dense internal `BIGINT` for joins and in-memory traversal.
- Node, layer, namespace, kind, and ordered typed key parts.
- An incarnation number so delete/recreate lifetimes are not merged.
- Optional unresolved-placeholder status for references seen before definitions.

Never hash a display name such as `vrf:id:uuid` without type information.
Integer `1`, string `"1"`, a UUID, and raw bytes are different key values.

A child resource may have a compound key containing the canonical key parts or
opaque ID of its parent plus a child-local part. For example, a plug-in may key a
path by `(parent_resource_id, path_id)`. It remains a first-class resource with
its own incarnation and intervals. The key is identity material, not an implied
edge: the plug-in must separately emit the time-valid parent/child relationship,
and the core never parses key fields to invent correlation.

### 5.2 State representation

Use a small stable envelope rather than a universal EAV table:

- Promoted columns: existence, admin state, operational state, severity,
  provenance, and quality where they apply.
- `state JSONB`: full plugin-defined properties.
- `unknown_fields JSONB`: per-field reason and evidence gap.
- Optional plugin-declared typed projection tables/indexes for commonly filtered
  values such as VRF, prefix, group ID, neighbor address, or result code.

A missing JSON key, an explicitly null value, and an unknown value are distinct.
Avoid a global GIN index over every state document until a measured query needs it.
Literal normalized-history search is now one such measured query at 125K-event
scale. After plug-in sensitivity declarations are final, publication should
materialize a revision-scoped, case-folded `safe_search_text` projection and
index it with PostgreSQL `pg_trgm`; exact substring verification remains the
core security boundary. Raw payloads and sensitive fields must never be placed
in that index. The demo uses the same contract through a bounded immutable
SQLite sidecar plus a bounded in-process result-posting cache; this keeps the
large safe-text corpus out of private Python memory and allows restart reuse.
The demo's optional external-content FTS5 trigram table supplies candidates only.
Every candidate is joined back to the authoritative safe-text table and checked
with exact literal substring semantics; short or parser-unsafe queries use the
same exact table scan. SQLite builds without the trigram tokenizer persist a
scan-only sidecar rather than changing results or reconstructing raw payloads.
An ordered safe-projection digest, strict ordinal and size bounds, and a stored
FTS vocabulary digest protect reopen reuse from stale document/index
combinations; FTS5's full source-aware integrity check runs before publication.

### 5.3 Core tables

| Table | Essential purpose |
|---|---|
| `analysis_revision` | Immutable input/plugin/config identity and publication state. |
| `artifact` | Nested archive inventory, hashes, sizes, media type, and parent. |
| `plugin_run` | Capability, worker status, diagnostics, counts, output hash. |
| `clock_domain` / `clock_transform_segment` | Offset, drift, uncertainty, and alignment evidence. |
| `snapshot` / `snapshot_observation` | Collection metadata plus per-resource/per-field capture ranges, completeness, provenance, quality, and source evidence. |
| `relationship_observation` | Status-observed edges and scoped collection-completeness markers; kept distinct from mutations. |
| `resource` | Dense ID, external ID, canonical typed key, and incarnation. |
| `event` / `event_resource` | Raw/normalized time, source order, action, outcome, payload, subjects, evidence. |
| `state_mutation` | Before/after/unknown changes derived from an event. |
| `relationship_mutation` | Timestamped add/remove of typed relationships; replacement is explicit remove plus add. |
| `causal_link` | Cross-event correspondence with confidence and evidence. |
| `resource_state_interval` | Half-open `[start_ns,end_ns)` versioned state, provenance, quality, and field-level unknowns. |
| `relationship_interval` | Time-varying typed edge with attributes, provenance, and quality. |
| `reconciliation_finding` | Reconstructed-vs-observed differences and coverage gaps. |
| `forwarding_interval` | Versioned canonical FIB/next-hop/failover/adjacency/tunnel projection. |
| `reconstruction_watermark` | Latest complete local time per revision/node/status-perspective/topology-projection scope, with absolute mapping range and evidence. |
| `topology_interval` | Plugin-projected, time-valid connectivity identity/status referencing canonical resources and relationships. |
| `reconstruction_coverage` | Per plugin/resource/field/relation scope counts and reason-coded omissions. |
| `analysis_diagnostic` | Origin/stage, structured code, severity, artifact locator, and safe message. |
| `timeline_bucket` | Optional cached level-of-detail data after profiling proves a need. |

Store time validity as `int8range` with canonical `[)` bounds, or as explicit
`start_ns`/`end_ns` plus equivalent constraints. Useful indexes include:

```sql
CREATE INDEX state_at_time
ON resource_state_interval
USING gist (revision_id, resource_id, valid_range);

CREATE INDEX relationship_from_at_time
ON relationship_interval
USING gist (revision_id, source_resource_id, valid_range);

CREATE INDEX event_history
ON event_resource (revision_id, resource_id, event_time_ns, source_sequence);
```

The composite GiST forms require `btree_gist`. Start with simpler B-tree indexes
on `(revision_id, resource_id, start_ns)` if measured plans are already good.
Bulk-load staging rows with PostgreSQL `COPY`; avoid one ORM object per event.

## 6. Temporal reconstruction

An observation is a constraint on one resource, field set, relationship, or
complete relationship collection during its own `[observed_min, observed_max]`
window. It is not permission to seed a global world at the import capture time.
Linked resources collected at different times remain a capture vector until
reconstruction proves a common instant. If no common instant is supported, an
"observed" route or consistency response returns that vector/range and must not
claim one point-in-time world.

Every `ReadOnlyWorld` therefore exposes a `WorldBasis`: reconstructed requested
and resolved time, an observed capture vector, an absolute-time mapping, or a
relative capture vector with the relevant ranges. Multi-node bases contain one
`ResolvedNodeBasis` per selected node, including clock domain, mapping method,
uncertainty, evidence, quality, or an explicit unresolved reason. State views
retain validity/capture ranges and evidence. Forwarding and consistency outputs
inherit/reference that basis instead of compressing several observation times
into one synthetic timestamp.

### 6.1 Preferred forward algorithm

1. Normalize observation and event clocks when evidence permits; retain every
   uncertainty window.
2. Select a coherent earlier checkpoint when available. Otherwise seed each
   resource/relationship only from an observation anchor whose capture window
   supports the replay start; every other value begins unknown.
3. Order events by normalized time, then source sequence and stable source ID.
4. Call plugin `apply(event, world)`; one event may emit multiple direct and
   derived state/relationship mutations.
5. Close prior half-open intervals and open new intervals.
6. Create checkpoints every configurable event count or elapsed time.
7. Treat later observations as individual reconciliation constraints. Never
   copy them backward merely to fill an unknown gap.
8. Record exact/best-effort/ambiguous/unknown output counts by resource, field,
   relationship type, and time range.

### 6.2 Final-snapshot reverse fallback

1. Initialize each resource or relationship at its own latest observation
   anchor, not at one global final time.
2. Traverse only events preceding the applicable anchor in reverse deterministic
   order; linked state outside its supported window is exposed to the reducer as
   unknown.
3. Call plugin `revert(event, world_after)`.
4. If a field or relationship cannot be recovered, close the known interval and
   create an unknown interval; do not copy the later value backward.
5. Replay each reconstructed span forward and report mismatches against every
   applicable observation constraint.

Checkpoints accelerate replay; they are derived cache, not new truth. Most
point-in-time API requests should read materialized intervals directly.

The core never propagates changes merely because a `depends_on` edge exists.
Only a version-specific reducer knows the proprietary update semantics.

## 7. Dynamic dependency graph

The graph at time `t` is an interval query, not one permanently mutable graph.
Persist edges relationally and hydrate only the selected-time, selected-depth
slice into compact adjacency arrays or `rustworkx`.

Graph queries require seed resources, direction, relation types, depth, and a
hard result cap. The UI should show collapsed summary nodes when the cap is hit.
Use Sigma.js/WebGL for an interactive filtered subgraph; do not send the global
100K-resource graph to the browser.

For a timeline lane whose dependency changes over time, intersect relationship
intervals with the viewport. Pack overlapping target intervals into deterministic
sublanes using interval partitioning (`O(k log w)`); aggregate when a configured
sublane cap is exceeded.

A separate graph database is not recommended initially. Reconsider only after
profiling proves that deep, arbitrary multi-hop traversal dominates and cannot be
served from interval slices plus an in-memory graph.

### 7.1 Topology projections and status perspectives

Connectivity projection and operational status are separate axes. Plugins
declare stable `TopologyProjectionDescriptor` IDs for their topology semantics
and `StatusPerspectiveDescriptor` IDs for independent layer-local status views,
such as control intent, programmed bridge state, or observed hardware. A
projection advertises supported perspectives and an optional display default;
the core validates the combination but never interprets the role as ground truth.
For simple multi-source status, the descriptor also chooses a generic
combination operator; the core executes that declaration but never chooses AND,
OR, quorum, or required-source semantics on the plugin's behalf.

The plugin materializes inferred topology as canonical resources and time-valid
relationships/status with provenance, quality, evidence, and unknown fields.
The core stores those intervals and serves historical slices. It does not infer
that `depends_on` means connectivity, resolve proprietary peer matching, or map
vendor status strings to usability. Conversely, a plugin does not align node
clocks, choose a substitute perspective, page API results, or fabricate state
outside its evidence range.

The logical worker hook is
`project_topology(TopologyProjectionRequest, ReadOnlyWorld)`. It streams one
bounded envelope whose payload is a resource, endpoint, or link record. Endpoint
references are exclusive unions of a canonical resource key and a declarative
plugin match reference. A match carries a namespaced matcher ID, typed arguments,
and plugin-resolved candidate keys; the core never implements the matcher.
Every envelope repeats projection/perspective IDs and carries usability, source
resource keys, tri-state existence, validity, provenance, quality, unknowns,
and evidence. The
coordinator validates declarations/references, enforces total record and byte
budgets, materializes intervals, and exposes them through the revision API.

An API query therefore names both `topology_projection_id` and
`status_perspective_id`. The same topology identity can be evaluated against
different layer status. A missing selected-layer value remains unknown without
deleting the topology object or borrowing another layer's value. Reachability
ground-truth policy remains a third route-analysis choice; it is not implied by
the topology projection or its display default.

Relative selectors resolve against the exact node/perspective/projection local
watermark and do not require a wall-clock transform. The core requires a
registered clock domain only for absolute selectors, preserves optional
absolute uncertainty ranges, and keeps an ambiguous relationship as a possible
link rather than promoting it to definite topology.

### 7.2 Multi-node topology assemblies

A multi-node result is an immutable **assembly** of existing analysis revisions,
not a new synthetic node revision. Every member records its member ID, node ID,
analysis revision, required/optional role, and the exact plug-in runs used for
that query. Projection and perspective references are therefore qualified by a
plug-in run; a coordinator never assumes that two devices use the same local
descriptor IDs or even the same set of plug-ins.

Resource references in an assembly are structured as
`(member_id, revision_id, resource_id)`. This remains true when two device
plug-ins emit byte-for-byte identical local keys. The core fans the query out to
each member, resolves its chosen temporal basis, applies independent budgets,
and merges bounded result pages. One unavailable or unsupported optional member
produces reason-coded partial coverage instead of deleting the member or failing
the other results.

Local projection plug-ins may emit bounded connector claims. Each claim names a
versioned claim contract, an opaque normalized value, its local endpoint, time
validity, quality, and evidence. Exact equality is a core operation only for a
claim contract that explicitly declares exact-token semantics. Rich peer
matching, corroboration, aliases, one-sided observations, ambiguity, and
cross-vendor policy belong to an allowlisted federation/linker plug-in. The
linker receives bounded normalized claims rather than artifacts or database
access and emits matched, ambiguous, unresolved, or conflicting candidate sets.

Shared media use the same graph algebra. A plug-in projects a subnet or other
connectivity domain as a `TopologyResourceRecord` vertex and projects every
interface-to-domain attachment as an ordinary `TopologyLinkRecord`. The core
orchestrates a selected federation/linker plug-in, then validates and renders
its returned bipartite node/interface-to-segment view; the core does not decide
that two non-exact claims identify one domain. It also does not expand a LAN
with N attachments into N-squared pairwise links. This preserves multiple
independent attachments from one node, as distinct from the physical members
inside one plug-in-described LAG attachment.

Only a declared, versioned exact-token matcher may be equality-grouped by the
core. Every atom in a compound key is recursively type-tagged, JSON-safe, and
assembly/matcher-version scoped. UUID, binary, numeric, and string atoms remain
distinct. Stable attachment identity excludes ephemeral plug-in run IDs, which
remain provenance only. Prefix parsing,
VRF/VPN disambiguation, VLAN/LAG/subinterface membership, interface/neighbor/
route corroboration, management or loopback exclusion, and external-network
classification remain plug-in/linker responsibilities. One visible attachment
is only single-sided under the selected query coverage; it is not automatically
external. Every domain and attachment retains temporal existence, validity,
quality, confidence, provenance, evidence, and unresolved semantics.
Resource-table preview pagination is independent of the bounded topology claim
projection and therefore cannot remove a subnet attachment.

Legacy pairwise inter-node links remain a route-trace compatibility projection,
not the physical shared-medium rendering. When segment records are present, the
physical view suppresses those route-only links to avoid drawing both models at
once. VPN domains carry a plug-in presentation plane and may be rendered in a
separate logical view without changing the core storage model.

The link-status UI may expose presentation-only element filters for subnets,
VLANs, physical interfaces, LAGs, and subinterfaces. These filters operate on
the plug-in-declared attachment model; the core never classifies a resource by
parsing its key or display label. Hiding a layer contracts that part of the
visual attachment chain without changing the reconstructed graph. In
particular, a hidden subnet remains an internal junction so a multi-access
network is not rewritten as misleading pairwise router links. Filter state is
client presentation state and has no effect on stored identities, temporal
existence, status, provenance, or topology-query results.

Absolute assembly queries map one requested instant independently through every
member clock. Relative queries resolve against the exact member/plug-in-run/
projection/perspective watermark and return a capture vector with
`simultaneity: not_implied`. A reconstruction context freezes those resolutions
and selections for navigation. Core-generated navigation targets use that
context to move from a fabric endpoint to the corresponding node resource and
back without re-resolving a later watermark or accepting plug-in-supplied URLs.

The browser route hierarchy mirrors that ownership. `/` is the primary
multi-node topology entry point, `/topology` is a compatibility alias for that
page, and core-generated topology actions open an assembly member in the
individual-node workspace at `/node`. The node workspace carries its frozen
context and exposes a return target to the primary topology page, so navigation
does not silently reconstruct a different time or member selection.

## 8. Route and forwarding calculation

The dependency graph is not a forwarding model. Each platform plugin projects
state into a core-versioned, discriminated forwarding IR. Version 1 contains
typed `VrfForwardingState`, `FibEntry`, `NextHopGroup`, `NextHop`,
`FailoverGroup`, `Adjacency`, `TunnelAction`, and `InterfaceForwardingState`
records. References use canonical typed resource keys, not display strings.
Individual IR records preserve the unresolved references and attributes that
their type declares; the enclosing `ForwardingMutation` carries provenance,
quality, and evidence for the projected change.

A `ForwardingMember` may also carry bounded
`ForwardingCandidateConstraint` values. Each constraint uses one opaque,
plug-in-owned `ForwardingPolicyScope`, optional traffic-class applicability,
and explanatory `ResolutionContribution` records. The core understands only
the declared generic comparison operation (`exclude_exact_scope`) and compares
the entire typed scope by equality. It does not parse ESI, bridge-domain,
route-reflector, AS-path, VLAN, or vendor identifiers. This is the common
ingress-dependent policy mechanism used by split-horizon and similar rules
without putting protocol semantics in core. The projection or federation
plug-in also declares whether the ingress-scope set is complete; an applicable
non-match with incomplete evidence remains unknown rather than being permitted.

Projection is incremental. `project_forwarding(request, world)` receives a
`ForwardingProjectionRequest` containing the negotiated IR version, fully
qualified `StatusPerspectiveRef`, optional bounded `ChangeSet`, and hard
output/world-read budgets. A request without changes streams the initial
bootstrap; later requests emit only affected `upsert`/`delete` mutations with
effective time and uncertainty. The core validates the IR version and
references, then opens/closes `forwarding_interval` rows. Conformance tests
periodically compare incremental output with a clean full projection so stale
derived objects cannot accumulate silently. A plug-in never performs LPM or
returns a final route answer; those algorithms remain core-owned.

Single-node route resolution at time `t` is:

1. Select active forwarding intervals.
2. Longest-prefix match in the requested VRF.
3. Apply the plugin-projected lexicographic `selection_rank` (lower wins), exact
   selected status when available, and explicit multipath grouping. Equal rank
   alone never invents ECMP.
4. Evaluate each plug-in-declared ingress-dependent candidate constraint
   against the request's typed traffic class and carried ingress policy scopes.
   Preserve blocked, not-applicable, and unknown decisions instead of deleting
   rejected candidates.
5. Recursively expand next-hop and ECMP groups.
6. Evaluate failover/admin/operational predicates.
7. Resolve tunnel and adjacency dependencies.
8. Detect cycles by exact `ForwardingTraversalStateKey` equality and enforce
   the independent recursion and branch budgets.
9. Return every viable branch plus rejected and unresolved alternatives and an
   explanation tree.

`ForwardingTraversalStateKey` includes member, status perspective, forwarding
object and domain, ingress resource, lookup and packet context, active policy
scopes, and `policy_scopes_complete`. Re-entering the same router is therefore
not enough to prove a loop: a decapsulation, service-chain hairpin, or new
lookup context may
legitimately revisit it. When the complete key repeats, core returns a
`ForwardingCycleReport` containing the first occurrence, the closing repeated
occurrence, and the exact closed state sequence. The closing occurrence remains
visible to callers; it is not deduplicated into the earlier node.

The request selects an observed capture vector or reconstructed time. The
response echoes that basis, resolved revision/time or capture ranges,
provenance, quality, and evidence so a caller cannot confuse an observed
forwarding object with a best-effort historical one.

PostgreSQL `inet` plus an appropriate GiST/SP-GiST operator class can serve LPM;
plugins may maintain an in-memory radix structure for batch calculations.
`rustworkx` shortest-path algorithms are for the future multi-node topology
analyzer, not a substitute for single-node FIB semantics.

### 8.1 Cross-node multi-path route traces

An end-to-end trace is a query over a frozen multi-node reconstruction context,
not a new topology fact. The request identifies the ingress assembly member,
VRF and destination, temporal basis or existing `context_id`, the per-member
topology projection and status perspective, an explicit reachability
ground-truth policy, a completeness policy (`strict` or `best_effort`), and
bounds for hops, branches, local candidates, and boundary matches. Reusing a
context is preferred because it fixes member revisions, plug-in runs, local
watermarks or absolute mappings, and federation-linker selection.

The visible topology projection is a display/query scope, not a ceiling on
node-local route evidence. A resolver may require another projection owned by
the same selected node plug-in set (for example EVPN control state while the
map shows an underlay view). The core evaluates that auxiliary projection at
the same member basis, records its separate evidence context, and keeps the
original topology context authoritative.

The core executes a bounded state machine:

1. Resolve the immutable context and validate the selected ground-truth layer
   for every participating member.
2. Run the core LPM and forwarding traversal over the ingress plug-in's projected
   IR, preserving the plug-in-owned candidate membership, group semantics,
   candidate constraints, and human-readable resolution text at that node's
   resolved basis.
3. Preserve the plug-in's explicit path-group semantics: `single_active` has at
   most one selected primary and separate standby candidates, whereas
   `all_active` contains every explicitly declared ECMP member. Equal rank or
   multiple viable candidates never invents ECMP.
4. Ask the selected federation linker to match each egress claim to bounded
   remote-ingress candidates. The core records matched, ambiguous, unresolved,
   and conflicting boundaries without guessing one.
5. Carry exact ingress policy scopes, their completeness, packet/lookup
   context, and traffic class across each matched boundary. Scope contract IDs
   are not globally interchangeable: the owning node or federation/linker
   plug-in must explicitly preserve a compatible contract or project a mapped
   remote scope. If it cannot, the receiving scope set is incomplete rather
   than a guessed non-match. Continue local resolution on every `PERMITTED` or
   `NOT_APPLICABLE` member; retain `BLOCKED` and `UNKNOWN` policy candidates
   with their plug-in evidence.
6. Detect an end-to-end loop only when the complete canonical traversal state
   repeats, and enforce hop, recursion, branch, local-candidate, and boundary
   budgets independently. Stop at the destination, a discard or policy-block
   action, a cycle closure, or an incomplete boundary.
7. Return stable ordered paths, rejected and unresolved alternatives, coverage, and
   cross-perspective consistency findings; never collapse disagreements into a
   single apparently exact answer.

Every path has a stable `path_id`, a role (`primary`, `standby`, `ecmp`, or
`alternative`), and `steps[]` in increasing `step_index`. Step identity is
derived from the frozen context, branch, member, canonical resource references,
and phase, rather than display text. The normalized phases are stable enough for
clients to render and compare: local lookup, candidate selection, next-hop or
failover evaluation, tunnel action, adjacency/egress, federation boundary, and
remote ingress. Node plug-ins own each local step's `resolution_text`, local
candidates, and mapping of proprietary status to selected/degraded/unusable/
unknown. The core validates references and ordering, inserts orchestration
envelopes, and never rewrites vendor meaning. The federation linker owns only
boundary candidate matching and its evidence.

For `single_active`, only the selected primary represents the forwarding path;
standbys are reported for failover explanation and must not be rendered as
concurrent traffic. If selection itself is uncertain, candidates are
alternatives rather than an invented primary. For `all_active`, all members of
an explicit multipath group are returned as concurrently eligible branches,
with plug-in-projected weights or selection metadata preserved. The core does
not infer load distribution from branch count.

Layer comparisons resolve the same flow independently under each requested
status perspective. They can therefore report different egress interfaces,
next hops, destinations, encapsulations, failure predicates, or termination
members. A consistency finding points to the first divergent stable step and
retains both complete ordered paths. One perspective may be named ground truth
for the query, but that choice is explicit policy and does not change the
provenance or quality of another perspective.

Under `strict`, a missing required member, unsupported perspective, unaligned
clock, unknown required status, or ambiguous/unresolved boundary prevents a
complete path. Partial prefixes may be returned for diagnosis, but `result`
remains incomplete and no guessed continuation is emitted. Under
`best_effort`, the core may explore bounded plug-in/linker candidates and return
provisional paths with reason-coded assumptions. Their evidence, quality,
unknown fields, and member-local observation times travel on every step and the
aggregate path. A best-effort path may be cached or exported only with those
semantics intact; it is never reused as ground-truth reachability merely because
later orchestration produced a continuous line.

In the topology UI, hover or keyboard focus on a resolution step highlights
exactly one plug-in-selected topology node or link and dims the other route
elements. Node and link chips in the ordered path rail expose the same
bidirectional correlation; shared endpoint resources do not broaden the focus
to adjacent steps. A bounded hover card shows
role, result, selected ground-truth perspective, hop count, egress and
encapsulation summary, first divergence, and uncertainty/coverage reasons.
Single-active standby and all-active ECMP branches use distinguishable semantic
styles in addition to color. Clicking pins path focus; selecting a step follows
a core-generated link to the exact member resource in `/node`, carrying
`context_id`, `path_id`, `branch_id`, and `step_id`. Returning restores the same
topology path focus. Hover alone never changes time, selection, or context.

## 9. Timeline and dashboard

### 9.1 Timeline response contract

Every request includes revision, visible lane IDs, `[start_ns,end_ns)`, viewport
pixel width, filters, and a maximum glyph count. The server returns:

- Exact state intervals when below the cap.
- Event clusters with counts by action/outcome/severity.
- First/last timestamps and representative event IDs.
- Worst severity plus status-duration fractions; never only dominant status,
  because that hides brief failures.
- Dynamic dependency spans and overflow summaries.
- The actual immutable revision and clock uncertainty.

Choose a bucket width that produces roughly one or two horizontal buckets per
pixel. Raw events are returned only when sufficiently zoomed in. A cluster drill-
down endpoint paginates exact events. The opaque `cluster_id` binds the immutable
revision, normalized query/filter digest, lane, and exact bucket bounds. Expansion
uses deterministic `(event_time_ns, source_id, source_sequence, event_id)` order
and an opaque cursor. A missing/expired cached aggregate can be recomputed from
that bound query; a mismatched revision or query digest is rejected rather than
silently expanding a different cluster.

Every lane has one immutable canonical resource ID. State intervals, lifecycle
intervals, event marks, and relationship spans on that row always describe that
resource. A relationship query may dynamically add or remove *rows* as the
selected time changes, but a row must never switch from one related resource to
another. This makes an operator's vertical comparison stable and keeps resource
selection independent from temporal selection.

A searchable lane chooser lets users add/remove types and individual resources,
drag lanes into a preferred order, and append any clicked related resource below
the current group. Hovering a mark shows a bounded summary; selection opens exact
events and provides an explicit jump to the raw CTF/text source locator. A
cluster summary exposes its count and a bounded preview, while the exact-event
endpoint supplies a deterministic scrollable remainder.

Log inclusion has one core-owned normalized-event stream plus zero or more
plug-in-declared source-record presentation groups.
`PluginSchema.source_record_groups` supplies opaque group IDs, labels,
descriptions, and default inclusion state; each
`SourceRecordTypeDescriptor.stream_group` references one declared group. The
browser renders these descriptors generically and submits explicit source-type
filters. A source-record group is only UI/query metadata: it is not a decoder
stream, a clock domain, or a storage partition. Names such as `ctf` and
`external` are demo plug-in vocabulary and must never be inferred by the core
from a source type or label.

### 9.2 Browser implementation

Recommended browser stack:

- React and TypeScript for UI composition.
- TanStack Virtual for vertical lane virtualization.
- PixiJS 8 for Canvas/WebGL intervals, event bars, clusters, and hit testing.
- D3 scale/zoom/brush utilities for time transforms and selection.
- Sigma.js for the filtered dependency graph.

Keep resource labels, sticky time ruler, controls, and accessible detail panels
as DOM elements. Render timeline marks in one canvas/WebGL surface. Accessibility
requires a keyboard-navigable event list mirroring the selected viewport; canvas
marks alone are not accessible.

Interaction mapping:

- Wheel: vertical lane scroll.
- Horizontal trackpad gesture or Shift+wheel: time pan.
- Ctrl/Cmd+wheel and pinch: zoom about pointer.
- Drag empty timeline: pan.
- Shift+drag: highlight range; explicit action zooms to it.
- Click empty track: select an arbitrary exact time.
- Click event: select the event and move the exact-time cursor without disabling
  empty-track clicks or range brushing; Enter opens the source context.
- Event inspection, exact-time cursor, and selected range are independent UI
  state. Selecting one does not silently clear or lock the others.
- Sticky ruler remains at the top only while the timeline viewport is active.

Hover cards use a short open delay and a grace interval while the pointer moves
between the glyph and card. The card remains interactive for scrolling, fades
only after leaving both regions, and can be pinned with a click. An exact mark
shows the operation, outcome, resource, resulting status, and duration to the
next accepted state change. A clustered mark adds total/failure counts and a
scrollable event list.

The main dashboard should report both failures and coverage:

- Parse errors and skipped artifacts.
- Clock alignment quality.
- Snapshot completeness by layer.
- PASS/FAIL/UNKNOWN consistency counts.
- Failed update chains and cross-layer propagation latency.
- Dangling/ambiguous relationships.
- Route/forwarding resolution success and unresolved branches.

It also provides one point-in-time table per plugin-declared resource kind.
Columns come from generic presentation descriptors and include current status,
status age, last event, failed updates, active correlations, quality, and
evidence. A plug-in may additionally declare a bounded relationship-tree table:
root kinds, ordered relationship hops, direction, optional target kinds, columns,
and expansion limits. The core traverses only relationships and endpoint
lifecycles active at the selected moment, so temporary children and paths appear
only for their valid intervals. Every nested row is still the same independently
addressable resource used by timeline lanes, events, and graph queries; visual
nesting does not change storage ownership. A selected range highlights
intersecting intervals/events and may show an endpoint state/correlation diff
without changing the point-in-time cursor.

Plugins can additionally compose modular dashboards from a small declarative
widget vocabulary. Each descriptor chooses declared resource kinds, safe field
paths, bounded filters, a common aggregate or table columns, and default
open/collapse/move behavior. The core validates descriptors when loading the
plugin schema and evaluates every module against one point-in-time resource
result; it does not branch on resource-kind names. The browser renders an index
of available modules at the end of the page, opens the plugin defaults, and
stores only presentation preferences—open modules, collapsed modules, and
ordering—in local storage. Reordering by drag or accessible move controls never
mutates analysis data.

Do not accept plugin-provided HTML, CSS, JavaScript, templates, remote URLs, SQL,
or expression-language programs for dashboards. New reusable widget types belong
in a versioned core contract with validation and query budgets. This preserves a
modular page without turning installed parser plugins into unrestricted frontend
code.

### 9.3 Frontend deployment boundary

Browser source is a standalone distribution under `frontend/`; the Python
source package contains backend and core logic only. A frontend-owned, versioned
manifest maps public page routes to HTML files and declares the asset directory.
The backend's generic host adapter validates that manifest, mounts only its
assets, and can be disabled entirely for split-process development. It does not
select page filenames, construct HTML, or expose the page directory below the
asset mount.

The integrated deployment remains same-origin because the browser clients use
root-relative, revision-scoped API URLs. A dependency-free development server
may host the pages separately when it reverse-proxies those paths to FastAPI.
That proxy is deployment tooling, not a plugin surface. Plugins still contribute
only validated data and presentation descriptors; they cannot ship executable
browser code or templates.

The source distribution and wheel must both include the frontend distribution.
An explicit `ROUTER_DUMP_FRONTEND_DIR` can select another complete build, while
`ROUTER_DUMP_SERVE_FRONTEND=0` or the demo's `--api-only` option leaves only the
backend endpoints enabled.

### 9.4 Why not a Python-only browser framework

FastAPI, parsing, correlation, reconstruction, APIs, and route logic remain
Python 3.12. A Trace Compass-like browser timeline with 100K items still needs
browser-native Canvas/WebGL code. Dash, Panel, or server-rendered templates can
prototype dashboards, but they do not remove JavaScript and would make the
custom lane interaction harder. Keep the TypeScript surface thin and domain-free.

## 10. API surface

Use immutable, revision-scoped endpoints and cursor pagination. Normative JSON
payloads, time-basis unions, pagination, and errors are in `docs/api-contract.md`:

```text
POST /v1/imports
GET  /v1/imports/{import_id}
GET  /v1/imports/{import_id}/events              # SSE progress
GET  /v1/imports/{import_id}/plugin-candidates
POST /v1/imports/{import_id}/plugin-selection
POST /v1/imports/{import_id}/resume

GET  /v1/revisions/{revision_id}/capabilities
GET  /v1/revisions/{revision_id}/resource-types
GET  /v1/revisions/{revision_id}/resources
GET  /v1/revisions/{revision_id}/resources/{resource_id}
GET  /v1/revisions/{revision_id}/resources/{resource_id}/history
POST /v1/revisions/{revision_id}/state/query
GET  /v1/revisions/{revision_id}/topology/providers
POST /v1/revisions/{revision_id}/topology/query
POST /v1/revisions/{revision_id}/topology/changes/query
GET  /v1/topology-assemblies/{assembly_id}/capabilities
POST /v1/topology-assemblies/{assembly_id}/query
GET  /v1/topology-contexts/{context_id}/members/{member_id}
POST /v1/revisions/{revision_id}/timeline/query
GET  /v1/revisions/{revision_id}/timeline/clusters/{cluster_id}/events?cursor=
POST /v1/revisions/{revision_id}/graph/query
GET  /v1/revisions/{revision_id}/events/{event_id}
GET  /v1/revisions/{revision_id}/events/{event_id}/source-context
POST /v1/revisions/{revision_id}/routes/resolve
GET  /v1/revisions/{revision_id}/consistency-findings
GET  /v1/revisions/{revision_id}/export?format=jsonl|arrow|parquet
```

Use `202 Accepted` plus a job resource for imports. Server-sent events are enough
for one-way progress; use WebSockets only if a later feature needs bidirectional
live control. If an endpoint accepts `latest`, resolve it once and return the
actual revision ID. Batch state queries are essential for dashboards.

Plugin selection includes the probe-set/inventory hash and exact plugin package
identity. A stale or concurrent choice returns `409`; repeating the same choice
or resume request is idempotent. Resume continues only from a validated durable
stage and never reuses partial unpublished output from a different plugin build.

Apply limits to upload size, selected lanes, graph breadth/depth, timeline span,
bucket count, raw context bytes, route recursion, and query duration.

## 11. Libraries

| Area | Baseline choice | Rationale and boundary |
|---|---|---|
| HTTP/API | FastAPI + Pydantic 2 + Uvicorn | Typed OpenAPI, streaming uploads, SSE. Heavy analysis is queued, never a FastAPI background task. |
| Jobs | Celery 5.6 with RabbitMQ; Redis acceptable for a small single-host profile | Linux worker processes, retries, limits, monitoring. Messages contain IDs only. |
| CTF | Babeltrace 2.1.2 `bt2`, pinned in a Linux decoder image | Babeltrace 2.1 adds full CTF 2 support through MIP 1. Treat it as a native dependency, not a normal pure-Python wheel. |
| Archives | Python `tarfile` + `zstandard` for a narrow known format set; `libarchive-c` when broad packaging support is real | On Python 3.12 explicitly apply `filter="data"`/`tarfile.data_filter` at every extraction layer, then stricter regular-file, path, collision, member/depth/expanded-byte/ratio rules. |
| Status parsing | Streaming line readers; TextFSM for stable table/line state machines; Lark LALR for genuinely nested grammars | Keep grammars inside version/platform plugins. Do not parse a 100K-line file with one giant regex. |
| Plugin discovery | `importlib.metadata.entry_points`; Pluggy only if hook ordering/wrappers become necessary | A small explicit protocol is easier to version and isolate. |
| Inter-process batches | Apache Arrow RecordBatch | Typed, columnar, bounded batches without per-row JSON overhead. |
| Serving data | PostgreSQL + psycopg 3 `COPY`; SQLAlchemy Core/Alembic for schema and ordinary queries | Concurrent server store and temporal/JSON/network indexes. Avoid hot-path ORM entity creation. |
| Overflow/offline analytics | Parquet + DuckDB; Polars inside plugins when columnar text transforms help | Add after profiling or for export; immutable files, coarse partitions, one publishing coordinator. |
| In-memory graph | rustworkx | Efficient directed/multigraph traversal and future shortest paths; retain stable external ID mapping. |
| Timeline | React, TanStack Virtual, PixiJS 8, D3 | Virtualized lanes and custom WebGL level-of-detail rendering. |
| Dependency graph UI | Sigma.js + Graphology | WebGL filtered subgraphs; server still owns temporal graph queries. |
| Observability | structlog, OpenTelemetry, Prometheus client | Structured job/plugin diagnostics with import/revision correlation IDs. |
| Testing | pytest, Hypothesis, testcontainers | Golden fixtures, malformed archive properties, reducer round trips, and real database plans. |

Do not pin these versions in prose forever. Lock and record exact versions in
the deployment image and in every analysis revision.

## 12. Performance design for 100K+

100K records is comfortable for PostgreSQL and a Python worker. The real risks
are interval multiplication, Python object overhead, repeated JSON decoding, and
trying to render everything.

- Stream archive members and Babeltrace messages.
- Parse and validate in bounded batches (for example 4K-64K rows after profiling).
- Use dense integer IDs in reconstruction and graph adjacency structures.
- Bulk-load staging tables and build expensive indexes after load.
- Reconstruct state/lifecycle intervals lazily for the bounded resource set a query touches; do not expand every event effect during ingest.
- A virtualized browser view must also avoid allocating one JavaScript wrapper per logical row; retain compact arrays and calculate visible rows and jump indices directly.
- Partition by revision/node/plane only when partitions are large enough; never
  partition by individual resource or tiny time bucket.
- Virtualize lanes and never send non-visible rows.
- Query/aggregate to the screen resolution.
- Cache only immutable revision queries and include resolution/filter keys.
- Benchmark with 100K, 1M, and a high edge-fanout case; a simple event count is
  not a sufficient load model.

Initial acceptance targets should be set by measurement on representative
hardware. Reasonable starting goals are: progress visible within one second,
viewport timeline response under 250 ms at p95 after warm-up, and no response
containing more than a few times the viewport's drawable glyph count.

## 13. Security and proprietary-data handling

Treat every dump as hostile and sensitive.

- Reject absolute paths, `..`, symlinks, hard links, devices, path-normalization
  collisions, excessive nesting, too many members, oversized expansion, and
  suspicious compression ratios.
- Extract only selected regular files into a private quota-controlled directory.
- Do not execute archive content or load a plugin supplied by a dump.
- Run native decoders/plugins with CPU, memory, file, process, output, and wall
  limits; disable network and provide no database credentials.
- Allowlist and pin plugin bundles; signing is preferable for production.
- Escape source text and never render log HTML.
- Add tenant/RBAC filtering to every artifact and revision query.
- Provide plugin redaction hooks, encryption at rest, retention/deletion policy,
  export audit logs, and safe diagnostic messages.
- Bound regex work and every graph/timeline/route query to prevent CPU denial of service.

Python 3.12 does **not** make the safer tar filter the default. Every core
materialization must explicitly use `filter="data"` (or `tarfile.data_filter`)
at every nested layer and then apply a stricter custom policy: normalized
relative names only, regular files only, no symbolic/hard links or device/special
members, no case/Unicode/path-normalization collision, and no destination escape.
Member count, nesting depth, cumulative expanded bytes, per-member bytes, and
compression ratio are checked while streaming. Plugins consume only the core's
validated `ArtifactReader` and may not extract archives themselves. The Python
documentation still requires archive inspection and additional resource limits.

## 14. Delivery sequence

### Milestone 0: contracts and fixture corpus

- Freeze canonical records, provenance/quality vocabulary, plugin API, and revision identity.
- Add synthetic bundles per platform/version and Babeltrace positive/negative traces.
- Test parser determinism, provenance, and malformed input limits.

### Milestone 1: ingestion and latest snapshot

- Safe inventory, explicit plugin selection, status/CTF parsing, artifact/source navigation.
- Latest observed state API and basic dashboard.
- No historical claims yet.

### Milestone 2: temporal reconstruction

- Forward/reverse reducers, clock domains, unknown propagation, state/edge intervals,
  reconciliation, and property-based reducer tests.

### Milestone 3: scalable timeline and graph

- Screen-resolution timeline API, virtualized WebGL lanes, dynamic dependency
  spans, filtered Sigma graph, and event-to-source navigation.

### Milestone 4: consistency and forwarding

- Tri-state rule engine, forwarding IR, single-node route resolver, and explanation trees.

### Milestone 5: multi-node preparation

- Stable export/API contracts, node clock/capture metadata, topology links, and
  `rustworkx` multi-node path algorithms. Do not merge node states until clock and
  revision semantics are explicit.

## 15. Choices intentionally deferred or rejected

- **Neo4j/Kuzu/another graph DB now**: dynamic validity intervals and revision
  publication are already relational; a graph DB adds operations before a proven need.
- **Kafka/ClickHouse now**: 100K-scale offline imports do not justify them.
- **Pure event sourcing without materialized intervals**: point-in-time UI queries
  would replay too much and make uncertainty harder to inspect.
- **Automatic dependency propagation**: a dependency edge does not define proprietary update semantics.
- **Callback success as hardware truth**: it is only evidence about callback handling.
- **Full graph/timeline transfer to browser**: violates the scale requirement.
- **Python-only UI promise**: incompatible with the requested high-performance browser interaction.

## 16. Primary references

- Babeltrace 2.1 release and CTF 2 support: https://babeltrace.org/docs/release-notes/babeltrace-2.1.0-release-notes.html
- Babeltrace Python bindings installation: https://babeltrace.org/docs/v2.1/python/bt2/installation.html
- Babeltrace Python iterator examples: https://babeltrace.org/docs/v2.1/python/bt2/examples.html
- Current CTF 2 specification: https://diamon.org/ctf/
- Python 3.12 `tarfile` and extraction filters: https://docs.python.org/3.12/library/tarfile.html
- Python entry points: https://docs.python.org/3.12/library/importlib.metadata.html#entry-points
- FastAPI uploads: https://fastapi.tiangolo.com/tutorial/request-files/
- FastAPI heavy background-task guidance: https://fastapi.tiangolo.com/tutorial/background-tasks/
- FastAPI server-sent events: https://fastapi.tiangolo.com/tutorial/server-sent-events/
- Celery brokers and result backends: https://docs.celeryq.dev/en/latest/getting-started/backends-and-brokers/index.html
- `libarchive-c`: https://github.com/Changaco/python-libarchive-c
- Python `zstandard`: https://github.com/indygreg/python-zstandard
- TextFSM: https://github.com/google/textfsm
- Lark parser: https://lark-parser.readthedocs.io/en/stable/
- PostgreSQL range types and GiST: https://www.postgresql.org/docs/current/rangetypes.html
- PostgreSQL JSONB: https://www.postgresql.org/docs/current/datatype-json.html
- Psycopg 3 and COPY: https://www.psycopg.org/psycopg3/docs/
- Apache Arrow columnar format: https://arrow.apache.org/docs/format/Columnar.html
- DuckDB Parquet pushdown: https://duckdb.org/docs/stable/data/parquet/overview
- DuckDB concurrency: https://duckdb.org/docs/current/connect/concurrency
- rustworkx API: https://www.rustworkx.org/api/index.html
- Sigma.js/WebGL: https://www.sigmajs.org/
- PixiJS particle-container guide: https://pixijs.com/8.x/guides/components/scene-objects/particle-container
- TanStack Virtual: https://tanstack.com/virtual/latest/docs/introduction
