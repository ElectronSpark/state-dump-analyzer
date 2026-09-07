# API payload contract

Status: normative `/v1` contract with implemented-surface notes
Encoding: UTF-8 JSON; Arrow/Parquet exports use equivalent typed columns

The endpoint list in `architecture.md` is intentionally compact. This document
fixes the payload rules other tools need. Sections that describe a target
rather than a shipped provider say so explicitly. The durable
`/v1/control-plane` catalog, ingestion, session, annotation,
correlation-report, and private-analysis run surface is implemented; its
operational guide is
[`control-plane.md`](control-plane.md).

## 1. Global rules

- Every analysis-data read is scoped to one immutable `revision_id`; a response
  that accepts `latest` resolves it once and returns the concrete ID.
  Control-plane catalog/list/mutation routes are instead scoped by trusted
  tenant plus project/workspace and return or select exact revision IDs.
- A `revision_id` is opaque and may contain `/`. Clients must URL-encode the
  complete ID when placing it in a revision-scoped URL and must not split it
  into path components. Servers expose path-aware
  `/v1/revisions/{revision_id}/...` routes so the decoded ID reaches revision
  lookup unchanged. The server binds revision-local data only after the router
  has parsed that path parameter; raw-path prefix matching is forbidden because
  overlapping IDs such as `a` and `a/inventory` are both valid.
- Nanosecond timestamps, counters that may exceed JavaScript's safe integer, and
  numeric key parts are decimal strings in JSON. Nanosecond request fields use
  the signed 64-bit domain. Browser-visible numeric paging offsets use the
  independent exact range `0..9007199254740991` (`2^53-1`), unless a route
  declares a smaller cap; `2^53` is rejected rather than rounded or echoed.
  Every other integer input has an explicit field-specific minimum and maximum
  (or a documented deliberately unbounded side), never an inherited timestamp
  default. Small counts and page sizes are ordinary JSON integers.
- Every caller-supplied audit cursor and watermark precondition uses canonical
  non-negative ASCII decimal syntax and the range `0..9007199254740991`. The
  same bound applies to retention `audit_before_sequence`, annotation
  `expected_audit_watermark`, review-audit `after_sequence`, and both retention
  journal cursors. Stored and projected catalog/review audit sequences use the
  same exact integer domain. Exhausted writes and out-of-domain stored rows fail
  closed rather than emitting an imprecise JSON integer.
- Half-open intervals use `start_ns` inclusive and `end_ns` exclusive; `null`
  means unbounded. Unknown time is not encoded as zero.
- `provenance` is one of `observed`, `event_derived`, `reconstructed`,
  `correlated`, or `plugin_default`. `quality` is one of `exact`,
  `best_effort`, `ambiguous`, or `unknown`.
- Missing, explicit `null`, known removal, and unknown values are distinct. An
  unknown field is listed in `unknown_fields` and omitted from `properties`.
- Page cursors and any cluster IDs are opaque, revision/query-bound strings.
  Clients must not parse them. The runnable demo's cluster-detail request uses
  the returned canonical lane resource and exact cluster time envelope as its
  expansion handle; it does not require the client to parse `cluster_id`.
  The current ordering migration emits temporal cursors internally versioned
  as `tt2` and server cluster IDs containing `server-v2`. An older temporal
  cursor is rejected, while an older cluster ID must be discarded because it
  cannot equal a current-order cluster. These strings remain opaque; the
  prefixes are documented only as stale-handle behavior, not client syntax.

### Static Python API surface

Python clients may consume the same models and provider interfaces through the
PEP 561 metadata shipped by all three repository distributions. The core,
demo, and independent scenario generator package roots contain `py.typed` and
one `.pyi` per Python module, so type checkers can resolve the complete public
surface after a normal installation. The stubs describe Python call signatures
and types; this document remains authoritative for JSON encoding, field
semantics, route availability, errors, and compatibility.

Repository drift and the representative strict consumer are checked with
`python scripts/export_type_stubs.py --check` and
`python -m mypy --python-version 3.12 --strict --no-incremental tests/typing/public_api.py state-dump-generator/tests/typing/generator_public_api.py`.

### 1.1 Browser workspace bootstrap

The generic core frontend obtains its runtime identity and scale behavior from
the API, never from demo names or resource vocabulary:

```http
GET /v1/workspace
GET /v1/nodes/{node_id}/workspace
```

Both responses contain a `workspace` object:

```json
{
  "workspace": {
    "workspace_id": "node-workspace:demo/node-a/revision-0001",
    "revision_id": "demo/node-a/revision-0001",
    "assembly_id": "router-state-lab-generated-demo-v1",
    "scope": "node",
    "workspace_kind": "node",
    "history_mode": "server-windowed",
    "capabilities": {
      "historical_state": true,
      "server_windowed_history": true
    },
    "node_id": "node-a",
    "node_label": "PE-A",
    "event_count": 1250005,
    "matched_event_count": 1250005,
    "resource_count": 7504,
    "source_record_count": 5000,
    "timeline_start_ns": "1759680000000000000",
    "timeline_end_ns": "1759680600000000000",
    "capture_ns": "1759680600000000000",
    "scale_mode": true,
    "large_dataset": true,
    "initial_resource_ids": [],
    "initial_focus_resource_id": null,
    "disclosure": "Synthetic generated node revision."
  }
}
```

`scope: node` means the resource/event payload belongs to exactly one immutable
node revision. A true bounded topology snapshot instead uses
`workspace_kind: point-in-time-snapshot`, `history_mode: point-in-time`, and
`capabilities.historical_state: false`; the browser must not imply history in
that case. A complete node history uses `history_mode: server-windowed` and a
matching top-level `history_transport.mode`. Event, source-record, density, and
detail endpoints in `history_transport` are revision-scoped.

For bounded node snapshots, the browser uses the recorded `node_snapshot`
query-node envelope: `resolved_basis.requested`, `resolved_basis.clock_policy`,
and the uniquely matching `node.plugin_results` entry. Its node/member/revision,
projection, perspective, and resolved-time identity must match the request.
Selector mismatches and topology API failures display an unavailable result;
the browser never reconstructs a replacement from local resources or events.
Recorded false/null existence and null clock bounds remain unchanged.

Counts describe the whole workspace, not the current page or DOM window.
`time_bounds` may repeat the three timestamp fields as a convenience.
`initial_resource_ids` and `initial_focus_resource_id` are generic bootstrap
hints whose values remain plug-in-owned resource identities. The coordinator
owns this envelope; plug-ins supply the node label, descriptors, counts, and
capabilities through their normalized output. Plug-ins never provide browser
URLs or executable frontend code.

Client publication applies property descriptors only inside plug-in-owned
payload containers: `state`, `key`, `properties`, `attributes`, `before`,
`after`, and `result`. A dotted descriptor name is a relative path through
nested mappings and lists and also matches an exact literal dotted key. It is
not a global key blacklist. Core structural fields such as revision, node,
resource and event identity, event `kind`/`action`, affected-resource
references, timestamps, interval bounds, descriptors, and capabilities remain
present with their core values even when a plug-in property has the same name.

Public `evidence`, `provenance`, `unknown_fields`, and `incarnation` values are
typed core metadata, not extension bags. The core keeps only their declared
bounded scalar shapes; device-specific metadata belongs in declared properties.
For event redaction, the core derives every involved resource kind from an
explicit event/subject/effect resource kind and from canonical resource IDs in
resource references and `affected_resources`, resolved against the immutable
resource catalog. Generic event `kind` is event classification, not a resource
kind. An unresolved reference, missing kind policy, or event with no determined
resource kind uses the conservative union of all declared sensitive fields and
condition policies; unresolved subjects cannot bypass private condition/status
redaction.
This publication boundary is identical for bootstrap, resource, search,
interval, range-summary, and event-query responses.
Nested event subjects, affected resources, effects, and relationship effects
are typed core envelopes rather than extension maps. Unknown children and
container values supplied for scalar core fields are omitted; device-specific
values must use a descriptor-governed payload container.

### 1.2 Core host and plug-in runtime binding

Every route documented here belongs to the core FastAPI application. A plug-in
cannot add, remove, replace, or wrap API routes, middleware, page templates, or
frontend assets.

Before startup, the core command loads exactly one module-level plug-in
instance and one input:

```text
router-dump-analyzer --plugin ENTRY_POINT_NAME --input PATH
router-dump-analyzer --plugin-module PACKAGE[.MODULE][:ATTRIBUTE] --input PATH
```

`/openapi.json`, `/docs`, and `/redoc` are absent by default. An operator may
enable them with `--expose-api-docs` only when the analysis listener is bound
to loopback. The CLI rejects the option for `0.0.0.0`, `::`, and every other
non-loopback host; programmatic launcher configuration enforces the same rule.

The installed-name form resolves the
`router_dump_analyzer.plugins` entry-point group. The direct-module form is for
source/development use and defaults `ATTRIBUTE` to `plugin`.

For an ordinary parser plug-in without `plugin.runtime`, core constructs
`router_dump_analyzer.runtime.v2`. It inventories the input, calls
`describe()`, `probe()`, and `locate_inputs()`, capability-dispatches the
selected parsers through a core `ArtifactReader`, validates every output, and
builds an immutable normalized revision. The plug-in receives logical artifact
IDs, read-only streams, and session-private materializations; it never receives
the original host path.

The current v2 session supplies a required `revision_store`, `data_source`, and
`data_policy` and serves the basic normalized node workspace. Its optional
`temporal_provider`, `topology_provider`, and `route_provider` are `None`, so
dependent APIs are unavailable rather than inferred from another provider or
device vocabulary. Its in-memory source currently exposes no structural
history index.

`plugin.runtime` with capability ID `router_dump_analyzer.runtime.v1` is a
compatibility adapter only for independently versioned precomputed fixtures.
When present, core enters `runtime.open(input_path)` for the application
lifespan and validates the same six session surfaces. Core constructs
`NormalizedDataService` from the source and policy; plug-ins do not implement
generic state, relationship, resource-table, dashboard, range, redaction,
search, or client-projection queries.

After the runtime session has opened, a frontend-hosted deployment leaves the
default revision lazy so the page and progress endpoint can become reachable
before parsing begins. Its first data request materializes the revision, and
the first indexed search builds the safe-search corpus, synchronously under
separate tracked load operations. API-only/headless startup performs those
same steps synchronously before serving so failures remain fail-fast. There is
no detached warm-up worker. Every core-bound
`NormalizedDatasetSource.load_dataset()` call owns a thread-safe progress
operation. A compatibility fixture loader may refine that operation through
`AnalysisLoadStage` and `report_analysis_load()`; reports are advisory,
path-free, numeric, and a no-op outside a core-bound load. Unknown work never
receives an invented percentage.

The default host enters that real application lifespan before handing control
to Uvicorn and disables Uvicorn's duplicate lifespan driver. Runtime open,
context entry, lazy discovery, serving, and context exit therefore share one
core-owned lifetime. An ordinary installed plug-in failure during startup exits
with status 1 and exactly one bounded, path-free
`router-dump-analyzer: error: ...` line, without a traceback. The
process-control exceptions `KeyboardInterrupt`, `SystemExit`, and
`GeneratorExit` propagate unchanged. This projection is preserved across the
declared `uvicorn>=0.30,<1` dependency range, including each generation's
native event-loop selection mechanism.

This binding does not alter payload ownership. Core still owns envelopes,
pagination, errors, routes, and rendering contracts. The plug-in still owns
input interpretation, resource and relationship meaning, topology/route
projection policy, redaction policy, and safe explanation text.

Runtime-v2 publication is fail-closed. Core rejects wrong output classes,
undeclared schema references, evidence outside the selected input, coercive
integer/boolean fields, invalid time bounds, unsupported or cyclic values,
non-finite floats, and configured artifact/discovery/output/nesting/size
overruns before the revision is exposed. It neither truncates a semantic value
nor publishes a valid prefix of an invalid parser stream.

Probe selection is not a weaker preflight. The durable registry uses the
registered coordinator's `ArtifactLimits`, and author validation, durable
selection, and direct ingestion all call the same complete probe-report and
diagnostic validators. A forged result or malformed diagnostic therefore
cannot be selectable and then fail only after consuming the ingestion retry
budget.

Optional semantic hooks have an executable Python caller but no plug-in-owned
HTTP surface. Host code imports `PluginCapabilityExecutor` from
`router_dump_analyzer` and uses its `apply`, `revert`, `correlate`,
`project_relationships`, `check_consistency`, `project_topology`,
`project_forwarding`, `resolve_forwarding_step`, and `analyze_evidence`
methods. The executor gates each call by the manifest,
bounds world reads and output iterators, validates requests and results against
the immutable schema, preserves recoverable diagnostics in typed result
envelopes, and raises a typed execution error for fatal or invalid output.
Caller-owned request validation instead raises the root-exported
`PluginCapabilityInputError` before the hook is resolved or invoked; malformed
plug-in output remains `PluginCapabilityOutputError`.
This makes the hook contract executable without implying temporal, topology,
or route providers; those runtime-v2 providers remain `None`. Durable
ingestion now schedules `RELATIONSHIP_PROJECTION` and then
`CONSISTENCY_CHECK` after the execution plan is frozen and before normalized
bytes are hashed. The primary participates when it declares the corresponding
capability. Auxiliaries require the exact `revision_relationship_projection`
or `revision_consistency` role in addition to the capability.

Every relationship projector receives the same immutable base revision world.
Its `RelationshipDeclaration` values have no timestamp, presence, basis, or
producer fields: core attaches the basis digest, plan digest, and exact
provider. Both endpoints must exist in the base world, the relation and
perspective must belong to the primary schema, attributes must be complete
with no removals, and evidence must belong to the revision. Canonically
identical declarations collapse with their contributions retained. Conflicting
claims remain distinct under a stable ambiguity group and produce one
conservative ambiguous edge containing only common attributes. The augmented
world, not the base world, is passed to consistency providers. Durable records
retain the complete declared attributes; public projections apply the primary
schema's descriptor-sensitive redaction rules to those plug-in-owned values.

For ordinary direct execution, a provider is validated against its own
schema. Scheduled materialization uses a private coordinator authority to
validate primary and auxiliary declarations against the primary revision
schema; there is no public schema-override parameter. Projection diagnostics
must be recoverable and use the exact `relationship_projection` stage.
Perspective qualification is part of edge identity, so equal endpoint/type
claims in different perspectives remain independent. An explicit parser edge
is authoritative over a projected edge only at the same fully qualified
perspective.

The canonical dataset contains `relationship_declarations`,
`relationship_projection_edges`, producer-qualified
`relationship_projection_diagnostics`, and a
`relationship_projection_materialization` envelope. It then contains
`findings`, producer-qualified `consistency_diagnostics`, summary counts, and
a `consistency_materialization` envelope whose status is `complete` or
`not_applicable`. Legacy revisions lacking the consistency envelope are
surfaced as `not_materialized`. A legacy revision predating relationship
projection simply lacks that projection envelope. Neither hook is recomputed
during a read.
`PluginCapabilityLimits` independently bounds basis capture ranges, node
resolutions, per-container evidence, and aggregate basis evidence before the
executor snapshots plug-in output; revision materialization applies its own
aggregate limits before publication.

The durable v1 envelope is a closed object containing `schema_version`,
`status`, `plan_digest`, `basis`, `basis_digest`, `providers`,
`provider_count`, `finding_count`, `diagnostic_count`,
`emitted_finding_count`, `emitted_diagnostic_count`,
`duplicate_findings_discarded`, `duplicate_diagnostics_discarded`, and
`world_reads`. A core-ingestion-v3 revision stores only `complete` or
`not_applicable`; `not_materialized` is a read-time compatibility projection
for older revisions. Readers revalidate envelope counts and limits, require
every evidence artifact to belong to the revision inventory, reconstruct typed
resource-key parts and rederive their canonical resource IDs, and enforce the
same list/value/byte domains before projection. A noncanonical or unsafe stored
record is a dataset-integrity failure, never a partially projected finding.

For PROCESS ingestion the complete plan still records every composed
auxiliary, while the child loads only the primary and exact auxiliaries
selected for scheduled materialization by
`REVISION_RELATIONSHIP_PROJECTION_ROLE` or `REVISION_CONSISTENCY_ROLE`. A
scalar pre-load check rejects any extra, missing, duplicated, reordered, or
mismatched auxiliary bootstrap. Each stage-specific router retains the full
plan digest but cannot route a pin outside its selected set; ordinary router
construction continues to validate the whole plan.

The relationship materialization envelope is a closed revision-scoped object
containing `schema_version`, `status`, `scope`, `plan_digest`, `basis`,
`basis_digest`,
`providers`, `provider_count`, `declaration_count`, `resolved_edge_count`,
`diagnostic_count`, `emitted_declaration_count`,
`emitted_diagnostic_count`, `duplicate_emissions_collapsed`,
`semantic_conflict_groups`, `world_reads`, and `base_resource_count`. Stored
declarations retain every canonical semantic claim and provider/evidence contribution;
stored resolved edges are the conservative relationships used to augment the
world. `valid_from_ns` and `valid_to_ns` remain absent because core does not
invent a comparable capture timestamp. As with consistency, a malformed or
over-budget stage aborts publication atomically rather than persisting a valid
prefix. Reload validates the complete basis and derives its digest instead of
trusting the digest field alone. It also reconstructs evidence, occurrence,
and serialized-byte charges before duplicate elimination, so deduplicated
storage cannot bypass ingestion limits.

The base world folds snapshot observations sharing one `ResourceKey` and
qualified status perspective; it retains the final ordered observation's
evidence for the resulting state. The projection API does not expose the raw
observations hidden by that fold.
Different perspectives retain independent states and intervals. Without a
selected perspective, a singular lookup covering multiple perspectives is
ambiguous (`exists: null`) rather than a merged state. Missing selected status
is unknown. Resource tables (including named bundled views) and topology both
preserve this tri-state existence: only explicit `false` means absent.
After the execution plan is frozen, core qualifies primary-parser local
perspective references using the exact primary pin before rebuilding the
published histories. Data without a plan remains unbound.
Undirected relationship endpoints are canonicalized before grouping, so an
oppositely ordered removal targets the same relationship within its perspective.
Explicit world-read limits equal to the remaining quota are accepted by both
materializers and the capability executor; unbounded over-quota reads still fail.

Runtime-v2 ingestion also validates and retains scoped
`RelationshipCollectionObservation` markers as private normalized metadata.
Their collection-completeness inference is not yet materialized into the public
relationship intervals or API payloads in this document.

### 1.3 Durable control-plane boundary

The implemented control-plane router is independent of the initial
single-input browser workspace. It is mounted at `/v1/control-plane` when the
server is started with `--control-plane-dir PATH`; otherwise its routes return
`503`. The core CLI installs `TrustedHeaderIdentityResolver` for this local
profile and permits it on loopback by default. A non-loopback bind is rejected
unless the caller explicitly adds `--trust-control-plane-headers`; that flag
is a development override, not an authenticated deployment.

Every request requires `X-Tenant-ID`; every mutation also requires
`X-Principal-ID`. The host must install a `ControlPlaneIdentityResolver` that
returns a verified `ControlPlaneIdentity` containing tenant, principal,
roles, and optional project/workspace allowlists. The router checks the
headers against that resolved identity, requires `control-plane:read` or
`control-plane:write`, and hides disallowed project/workspace scope as `404`.
Retention routes require `control-plane:admin` instead of the ordinary read or
write role; those roles need not be granted as well. The CLI's
explicit local adapter trusts headers and grants exactly read, write, and
admin by default; it is not authentication. On a loopback listener only,
`--grant-instance-operator` explicitly adds the distinct
`control-plane:instance-operator` role. The option grants a role rather than
access to one current route, and is rejected with a production resolver or a
non-loopback listener. A production deployment verifies credentials upstream,
strips client-supplied identity headers, and constructs the resolver result.
The local adapter accepts only the configured exact `Host`, and a mutation's
optional `Origin` must match the configured HTTP origin exactly.
Tenant administration never implies instance operation. The operational
diagnostics route requires the exact instance-operator role.

The production-shaped core entry point hosts this surface without a startup
analysis or browser application:

```text
router-dump-server --plugin-deployment-module PACKAGE:ATTRIBUTE --state-dir PATH \
  --identity-resolver-module PACKAGE:ATTRIBUTE --host HOST --port PORT
```

Repeatable `--plugin NAME` remains the ordinary installed allowlist and
repeatable `--plugin-module PACKAGE[:ATTRIBUTE]` is the source-tree development
form. Those two families and the single trusted
`--plugin-deployment-module PACKAGE:ATTRIBUTE` descriptor are mutually
exclusive. A descriptor returns an exact `PluginCompositionDeployment` (or is
a factory called once with the canonical state directory) and binds primary
registry, provider directory, policy, and deployment digest together. The
descriptor holds sealed exact registry snapshots; later mutation of the
factory's caller-owned registries cannot alter its digest or authority. The server requires exactly one
identity mode; `--trust-control-plane-headers` replaces the resolver only on a
loopback bind. `--grant-instance-operator` is valid only with that trusted
mode and the same loopback restriction. The module resolver is synchronous and returns a verified
`ControlPlaneIdentity`. This API-only application mounts aggregate root
`/health` and `/v1/control-plane`; it has no input argument, startup-runtime
`/v1/revisions` routes, frontend, or static assets. The workspace-scoped
durable inspection query below does not require a startup runtime and is
available on this server. OpenAPI JSON, Swagger UI, and ReDoc are
absent by default. The server CLI exposes them only after an explicit
`--expose-api-docs` on a loopback bind and rejects that option on non-loopback
listeners. The durable plug-in allowlist is fixed at construction and cannot
be expanded by an upload.

`PluginCompositionDeployment(..., allow_inline_only=True)` is an explicit,
descriptor-owned trusted-local opt-in. It cannot be selected by HTTP, an
uploaded fixture, or another plug-in hook. Its deployment-v2 digest binds the
flag. `requires_inline_execution` is computed across every frozen primary and
provider record, including unused historical providers; if true, all primary
probe and parsing for that deployment run inline. The default descriptor remains
strict and PROCESS-only. The publisher remains PROCESS by default unless the
embedding separately overrides its execution mode.

The interactive analyzer can mount the same durable surface beside one
immediate single-input analysis. Its selectors remain independent:

```text
python -m router_dump_analyzer \
  --plugin-module PACKAGE[:ATTRIBUTE] --input PATH \
  --control-plane-dir STATE_PATH \
  --plugin-composition-deployment-module PACKAGE:ATTRIBUTE
```

The required ordinary plug-in selector owns only the startup input. The
composition descriptor owns only the embedded durable control plane. The
embedded descriptor option is invalid without `--control-plane-dir`; it is not
an alias for the standalone roots' `--plugin-deployment-module`.

`GET /context` returns resolved identity, explicit capability booleans, a closed
identity-mode label, and the visible project page:

```json
{
  "enabled": true,
  "tenant_id": "tenant-a",
  "principal_id": "analyst@example",
  "can_write": false,
  "can_admin": false,
  "can_instance_operator": false,
  "identity_mode": "deployment",
  "configuration": { "owner": "deployment", "editable": false },
  "limit": 1000,
  "offset": 0,
  "next_offset": null,
  "projects": []
}
```

`can_write: false` does not imply that reads or explicitly selected report
generation are unavailable. It means all mutation routes require a different
authorized identity and return `403` for this one.
`identity_mode` is `trusted_headers` only for the exact built-in local resolver;
other resolvers, including subclasses, are labeled `deployment`. Neither this
label nor a capability boolean authenticates the caller. Configuration is
deployment-owned and read-only: context exposes no resolver attributes, host
paths, credentials, environment values, or editable server settings. Ordinary
context access still requires `control-plane:read`; admin/operator roles do
not imply that role.

Create/admit mutations accept `Idempotency-Key`. Plug-in selection and
private-analysis run creation require that header. Private-analysis execute
and cancel require `If-Match` with the current strong numeric run version.
Session update/delete, session member/snapshot mutation,
annotation/correlation patch/delete, and import cancellation require
`If-Match` with the current non-negative integer version. The executable
accepts exactly one strong, quoted, canonical non-negative decimal validator
such as `"3"` and emits `ETag: "4"` on versioned object responses. It rejects
bare integers, weak validators, wildcards, lists, signs, whitespace, and
leading zeroes. Missing required preconditions return `428`; stale versions
or conflicting idempotency keys return `409`.

The scope hierarchy is:

```text
tenant
`-- project
    `-- workspace
        |-- immutable fixtures
        |   `-- immutable analysis revisions
        |-- versioned private-analysis disclosure policy
        |-- durable private-analysis runs, terminal reports, and proposal decisions
        |-- mutable sessions -> immutable revision-set snapshots
        |-- durable imports
        `-- mutable annotations/correlations -> append-only review audit
```

All paths below are relative to `/v1/control-plane`.

| Method | Path | Implemented purpose |
|---|---|---|
| `GET` | `/health` | Session-independent durable worker and queue health; no tenant identity required. |
| `GET` | `/diagnostics/operational-events` | Payload-free instance diagnostics; requires `control-plane:instance-operator`. |
| `GET` | `/context` | Confirm resolved identity, write/admin/operator capabilities, deployment-owned configuration status, and visible projects. |
| `GET, POST` | `/projects` | List or create tenant projects. |
| `GET, POST` | `/projects/{project_id}/workspaces` | List or create project workspaces. |
| `GET, PUT` | `/projects/{project_id}/workspaces/{workspace_id}/private-analysis-policy` | Read the current workspace disclosure policy or append an admin-authorized compare-and-swap revision. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/private-analysis-capabilities` | Read the core-owned, policy-filtered workflow and deployment-ceiling descriptors. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/private-analysis-runners` | List detached local runner identities allowed by the current workspace policy. |
| `GET, POST` | `/projects/{project_id}/workspaces/{workspace_id}/private-analysis-runs` | Page scoped run summaries or admit one derived, idempotent request. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/private-analysis-runs/{run_id}` | Read one payload-free run summary and strong version ETag. |
| `POST` | `.../private-analysis-runs/{run_id}/execute` | Execute the exact queued run under its durable fence; requires `If-Match`. |
| `POST` | `.../private-analysis-runs/{run_id}/cancel` | Commit cancellation before signalling a matching local attempt; requires `If-Match`. |
| `GET` | `.../private-analysis-runs/{run_id}/report` | Read a display-safe projection of the terminal query and advisory outcome. |
| `POST` | `.../private-analysis-runs/{run_id}/proposals/{proposal_id}/decision` | Durably reject or explicitly promote one digest-pinned proposal from a separately authored human target; requires `If-Match` and `Idempotency-Key`. |
| `GET` | `.../private-analysis-runs/{run_id}/proposal-decisions` | Page the run's durable human decision receipts. |
| `GET` | `.../private-analysis-runs/{run_id}/proposal-decisions/{decision_id}` | Read one scoped decision and strong version ETag. |
| `POST` | `.../private-analysis-runs/{run_id}/proposal-decisions/{decision_id}/recover` | Explicitly resume one pending human promotion; requires the decision `If-Match`. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/fixtures` | List immutable fixtures. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/revisions` | List immutable revisions; optional `node_id` or `fixture_id`. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/revisions/{revision_id}/consistency-findings` | Page durable, schema-redacted consistency findings and their materialization envelope. |
| `POST` | `/projects/{project_id}/workspaces/{workspace_id}/analysis/query` | Read one bounded client-safe page from an explicit durable revision/session/snapshot selection; requires read, not write. |
| `GET, POST` | `/projects/{project_id}/workspaces/{workspace_id}/sessions` | List or create mutable sessions. |
| `GET, PATCH, DELETE` | `/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}` | Read, update, or permanently delete one session. |
| `PUT, DELETE` | `/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}/members/{member_id}` | Add/replace or remove one exact fixture/revision member. |
| `POST` | `/projects/{project_id}/workspaces/{workspace_id}/sessions/{session_id}/snapshots` | Freeze the current member vector. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/snapshots` | List immutable snapshots; optional `session_id`. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/snapshots/{snapshot_id}` | Read one immutable snapshot in workspace scope. |
| `GET, POST` | `/projects/{project_id}/workspaces/{workspace_id}/imports` | List or raw-body upload imports. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/imports/{import_id}` | Read import state. |
| `GET` | `.../imports/{import_id}/candidates` | Read the deterministic probe candidates. |
| `GET` | `.../imports/{import_id}/events` | Page stored progress events. |
| `GET` | `.../imports/{import_id}/events/stream` | Stream progress as SSE. |
| `POST` | `.../imports/{import_id}/selection` | Select an exact candidate from the current probe set. |
| `POST` | `.../imports/{import_id}/resume` | Requeue a failed import within its attempt budget. |
| `POST` | `.../imports/{import_id}/cancel` | Cancel an eligible non-terminal import. |
| `GET, POST` | `/projects/{project_id}/workspaces/{workspace_id}/annotations` | List or create annotations. |
| `GET, PATCH, DELETE` | `.../annotations/{annotation_id}` | Read, update, or tombstone an annotation. |
| `GET, POST` | `/projects/{project_id}/workspaces/{workspace_id}/correlations` | List or create manual event correlations. |
| `GET, PATCH, DELETE` | `.../correlations/{correlation_id}` | Read, update, or tombstone a correlation. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/review-audit` | Page append-only review mutations. |
| `POST` | `/projects/{project_id}/workspaces/{workspace_id}/correlation-report` | Download deterministic JSON or Markdown. |
| `POST` | `/projects/{project_id}/workspaces/{workspace_id}/retention/preview` | Return a bounded, non-mutating catalog/review/ingestion inventory. |
| `POST` | `/projects/{project_id}/workspaces/{workspace_id}/retention/execute` | Run an admin-only, idempotent maintenance saga. |
| `GET` | `/projects/{project_id}/workspaces/{workspace_id}/retention/audit` | Return bounded store-specific retention journals. |

Here, an abbreviated `...` preserves the same project/workspace prefix.

#### Scoped durable analysis query

`POST .../analysis/query` is a read-only POST. It requires `X-Tenant-ID` and
`control-plane:read`; `X-Principal-ID` is optional, but must match the verified
identity when supplied. It does not require `Idempotency-Key` or `If-Match` and
does not mutate catalog records or the application-wide startup runtime.
Responses have `Cache-Control: no-store`. Its body is a closed object:

```json
{
  "selector": { "session_id": "comparison" },
  "selected_member_id": "before",
  "section": "events",
  "limit": 50,
  "offset": 0,
  "search": "interface",
  "start_ns": "100",
  "end_ns": "200"
}
```

`selector` contains exactly one of a nonempty unique `revision_ids` array,
`session_id`, or `snapshot_id`. Revision arrays and resolved member vectors
contain 1–128 members. Every member is checked against the authorized catalog
scope before the selected dataset is loaded. Distinct revisions of one node
remain separate members; the query never coerces a session into a topology
assembly with unique node IDs.

| Optional field | Contract |
|---|---|
| `selected_member_id`, `selected_revision_id` | Select within the resolved vector. If both are present they must identify the same member. Otherwise use the session/snapshot default, then the first member. Explicit revision vectors use each revision ID as its member ID. |
| `section` | `summary` (default), `resources`, `events`, `relationships`, or `findings`. |
| `limit`, `offset` | Canonical integers; limit 1–500, default 100; offset 0–9007199254740991, default 0. |
| `search` | At most 256 printable characters; case-insensitive literal match against the section's client-safe JSON projection. Not accepted for `summary`. Private/omitted fields cannot create a match. |
| `time_ns` | Signed 64-bit canonical integer coordinate; selects resource/relationship observation state. Defaults to the selected revision's timeline end. It does not filter events or re-evaluate findings. |
| `start_ns`, `end_ns` | Paired signed 64-bit coordinates with start ≤ end, accepted only for `events`; inclusive event-time range. |
| `expected_revision_vector_digest` | Optional exact `sha256:` digest returned by the previous response. A changed member vector or default member returns `409` before dataset loading. |

Send nanoseconds as decimal strings to preserve precision. Negative coordinates
are accepted by the signed query domain; the revision's declared time basis
still governs interpretation, with no invented cross-node alignment. Unknown
fields, duplicate/empty selectors, unrecognized sections, reversed/partial
event ranges, or out-of-bounds values return `422`.

The response contains:

```text
scope: { tenant_id, project_id, workspace_id }
selection: {
  kind: "revisions" | "session" | "snapshot",
  session_id?, snapshot_id?, version?: decimal string,
  revision_vector_digest: "sha256:..."
}
revision_vector: [{ member_id, fixture_id, revision_id, node_id, role, identity_digest }]
selected_member: one exact revision_vector item
section: summary | resources | events | relationships | findings
time_ns: decimal string
timeline: { start_ns: decimal string, end_ns: decimal string, time_basis }
capabilities: { sections, route: { available: false, reason }, topology: { available: false, reason } }
items, total_count, count, limit, offset, next_offset
```

The `relationships` section includes two separately labeled evidence classes.
`record_kind="temporal_observation"` uses the existing selected-time observation
reconstruction. `record_kind="revision_projection"`, `scope="revision"` exposes
validated projected edges with `present=null`, an explicit `temporal_note`,
canonical endpoint IDs and retained basis/execution-plan digests. It never adds
validity timestamps, overrides parser observations, or claims the edge was
present at `time_ns`. Its correspondence semantics still belong to the producer.
Projection attributes, raw evidence and private fields are not exposed by this
inspection projection. Summary `relationship_count` includes stored observation
and projected-edge records; `relationship_observation_count`,
`relationship_projection_count` and `relationship_declaration_count` distinguish
them. Interval count remains separate. Counts describe records, not effective
network adjacency or successful forwarding.

`selection.version` is the live session version or snapshot's captured session
version, not a new runtime version. The vector digest binds the ordered member
identities and default member, not a server-side analysis handle. The client
should retain it for subsequent pages or choose an immutable snapshot. A
deliberate refresh of live membership may omit it. `timeline.time_basis` is
`absolute_unix_ns`, `revision_start_relative_ns`, or null when this inspector
does not publish a recognized basis; no cross-revision clock equivalence is
implied. `total_count` is the exact matched count for that request, `count` is
the returned row count, and `next_offset` is null at the end.

Summary rows contain resource, event, relationship, relationship-interval, and
finding counts plus the client-safe consistency materialization envelope.
Resource rows reuse the normalized engine's lifecycle/status reconstruction
and descriptor-based state/key redaction; missing or ambiguous observations
stay unknown rather than inferred from event labels. Event rows contain closed
identity/time/action/outcome/quality fields and resource-subject identities,
not arbitrary event attributes or raw evidence locators. Relationship rows
reuse the existing embedded-history lifecycle/validity rules and expose only
closed endpoint/type/time/quality fields and tri-state presence: `present: true`
for confirmed or legacy-present edges, `present: null` for an explicitly unknown
observation. Absent edges are excluded; the inspector labels unknown presence
instead of presenting it as confirmed connectivity. Findings use the existing schema-aware
client projection, including closed basis/producer/evidence records with raw
locators omitted. Findings are materialized facts, not newly executed rules.

The existing durable loader verifies workspace ownership, safe dataset
location, configured byte limits, SHA-256, and published ingestion/plan
identity. No arbitrary dataset metadata or host settings is projected by this
query. Route providers, topology providers, parsers, and private models are
not invoked; the advanced route/topology capabilities remain unavailable.

The JSON request and response ceilings are each 1 MiB. An oversized result
fails with bounded `422`; request fewer rows rather than accepting a silently
truncated page. There is no fixed input-record-count rejection: the existing
configured dataset-byte ceiling remains authoritative. Unfiltered event pages
project only returned rows, including in the 1.25-million-event regression.
Search scans client-safe projections, relationship reconstruction scans its
stored observation collections, and the verified loader currently decodes or
reuses then deep-copies the selected dataset per request. This is a bounded
inspector, not a new on-disk million-row query index or startup-runtime binding.

#### Other durable records

Consistency finding pages accept `limit` from 1 through 5,000 and a
JSON-safe non-negative `offset`. They return `items`, `count`, `total_count`,
`offset`, `limit`, `next_offset`, the exact `revision_id`, and the detached
materialization envelope. Cross-workspace revision IDs are concealed as 404.
Typed resource-key atoms remain in the durable dataset for exact offline
analysis but are omitted from HTTP; public findings retain stable
`resource_id` references. Plug-in-owned `details` pass through
descriptor-sensitive property redaction. Core-owned finding basis, producer,
and evidence use closed field-and-domain allowlists; evidence `locator` is
always omitted, while artifact/time/hash coordinates remain when valid. The
materialization `basis_digest` commits to the richer durable basis rather than
this reduced public projection. The single-node
runtime route
`GET /v1/revisions/{revision_id}/consistency-findings?limit=&offset=` uses the
same bounded page shape and client projection.

The private-analysis policy `GET` returns a numeric strong `ETag`. An
unconfigured workspace returns `ETag: "0"`, `explicit: false`, and the closed
`disabled` policy; workspace metadata never changes this result. `PUT` requires
`control-plane:admin`, the current ETag in `If-Match`, and this exact body:

```json
{
  "policy_version": "router_dump_analyzer.workspace_disclosure_policy.v1",
  "mode": "full_fidelity",
  "transports": ["in_process"]
}
```

`mode` is one of `disabled`, `client_safe`, or `full_fidelity`. A disabled
policy has no transports; an enabled policy has a unique, canonical-order list
drawn only from `in_process` and `local_subprocess`. Unknown keys, duplicate or
out-of-order transports, and public/network transports are rejected. Updates
append immutable history and use optimistic versions rather than overwriting a
prior policy. Core validates a workspace-rooted hash-chain tip, the durable
head, exact-revision receipts, and contiguous history on read and write; a
missing or independently corrupted revision is a storage failure, never an
implicit rollback to an older permission. This integrity contract assumes the
SQLite catalog file, schema, triggers, and state-directory administrator are
trusted. It does not claim to detect a privileged actor coherently replacing
every authority row or restoring the complete catalog from an older snapshot.

Each revision item includes `execution_plan`. New durable publications expose
the closed `router_dump_analyzer.plugin_execution_plan.v4` object: node and
source-revision basis, ordered producer pins, optional decoder identity, and
the exact `composition_policy_digest`, closed `execution_plan_authority`, and
`plan_digest`. `PluginExecutionPlanAuthority` is the weakest whole-plan value:
`process`,
`trusted_inline_attested`, or `trusted_inline_manifest`. A pin exposes
artifact/configuration/schema/capability/role and
content-addressed registered-execution identity but never configuration
values. A PROCESS pin's `process_bootstrap_digest` separately commits to the
complete non-recursive
process-reconstruction bootstrap (all loader kinds/targets, each external
target's source-backed executable identity, verification mode, frozen
ingestion/artifact limits, and reconstruction coordinates); only its
self-referential expected-identity member is excluded, and the child validates
that commitment before importing any target. Trusted-inline v4 pins carry
`process_bootstrap_digest: null`. `plugin_ids` is the
ordered distinct
projection of the plan's plug-in IDs and must agree with it. The normalized
dataset `_ingestion.plugin_execution_plan_digest`, catalog metadata, plan body,
and correlation-report revision vector identify the same plan. A migrated
pre-contract row returns `execution_plan: null`; absence is not proof of the
current registry state. Unfinished pre-contract queue entries clear their old
candidates and selection, atomically adopt the composition policy explicitly
active for the upgrade, and are re-probed before execution. Already staged or
completed legacy publications keep their historical policy and remain
planless, so idempotent crash replay uses the original payload.

The strict reader retains v1, v2, and v3 with their original byte/shape/digest
contracts. A
retained v1 pin has no `registered_execution_identity`, and its plan has no
`composition_policy_digest`; decoding uses reserved all-zero sentinels only
inside the passive value. V2 requires both fields, rejects either reserved
legacy-zero value, remains executable, and decodes its historically absent
authority as `legacy_unrecorded` rather than claiming PROCESS. V3 adds the
closed authority field. V4 adds the per-pin bootstrap commitment for PROCESS
plans without rewriting retained history. Every version is bounded to 512 KiB of canonical plan
JSON. V1 remains
readable in catalog responses but cannot bind a capability provider, execute a
capability, or produce private-analysis evidence.

Exactly one pin has role `primary_parser`; the compatibility `plugin_id` and
`plugin_version` fields name that pin. Additional pins may name configured
capability providers, including several instances of one plug-in/version.
Clients MUST retain `instance_id`, roles, and `plan_digest`; `plugin_ids` is a
display/index summary and cannot route a call. There is not yet a public HTTP
endpoint for optional-capability routing. In-process coordinators use the
core-owned `PlanBoundCapabilityRouter`, which fails for a null plan and returns
producer-qualified results through typed capability methods. The router and
provider registry are trusted in-process composition objects; underscore
attributes and Python introspection are outside the supported API and are not
a sandbox for hostile in-process callers.

`process` describes only primary ingestion and does not claim that later
capability hooks execute behind a subprocess boundary. An opted-in inline-only
provider can be routed only when the plan records a trusted-inline authority
and the router receives the same deployment policy. The manifest tier is not a
code-reproducibility claim: it freezes and revalidates manifest/registered
identity but cannot attest implementation bytes.

The core-owned in-process consumer is
`ControlPlane.capability_router_for_revision(scope, revision_id, member_id=None)`.
`ControlPlane.capability_router_for_revision_set()` requires exactly one of a
non-empty `revision_ids` vector, `session_id`, or `snapshot_id`; it admits 1 to
128 distinct members, preserves catalog member IDs for sessions/snapshots, and
uses revision IDs for an explicit vector. Both return plan-bound routers and
fail closed for a planless, stale, missing, or ambiguous provider. No public
HTTP route exposes plug-in objects or an unqualified capability call.

The exported private-analysis evidence values are also implemented. There is
no direct `/v1` evidence browser or payload-read route; the authorized run
lifecycle described below exposes only derived request/run metadata and a
terminal display projection. An atomic reference has this
exact shape (digest text is abbreviated here only for readability):

```json
{
  "contract_version": "router_dump_analyzer.private_analysis.evidence_reference.v3",
  "scope": {
    "tenant_id": "tenant-a",
    "project_id": "project-a",
    "workspace_id": "workspace-a"
  },
  "revision": {
    "fixture_id": "fixture-a",
    "fixture_content_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "node_id": "router-a",
    "revision_id": "revision-a",
    "revision_identity_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "plan_basis_revision_id": "dump-basis-a",
    "execution_plan_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333"
  },
  "producer": {
    "authority": "plugin_inferred",
    "producer_id": "vendor.router",
    "plugin_instance_id": "parser-a",
    "plugin_capability": null,
    "plugin_role": "primary_parser"
  },
  "kind": "source_record",
  "subject_kind": "lttng_event",
  "locator_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
  "evidence_class": "proprietary",
  "payload_schema": "vendor.lttng.event.v1",
  "fact_provenance": "observed",
  "time_range": {
    "basis": "revision_start_relative_ns",
    "start_ns": "17",
    "end_ns": "17",
    "uncertainty_ns": "2",
    "clock_domain": null
  },
  "content_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
  "reference_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666"
}
```

The reference is projection-bound and contains no raw locator. Current version
3 requires a plug-in producer to name exactly one declared capability or one
execution-plan role; generic normalized records use the exact
`primary_parser` role because parsing is a role in the immutable plan rather
than an optional capability route. Version-1 capability-qualified references
remain readable and retain their original wire/digest shape. Version 2 adds
role-qualified producers and unknown time; version 3 adds only the closed
`plugin_capability_result` kind and `plugin_analyzed` provenance. V1/v2 cannot
carry those v3 semantics. The closed
`kind` names a core category, and `fact_provenance` is also closed general core
vocabulary; `subject_kind` and `payload_schema` retain producer vocabulary.
Arbitrary assistant or mutable-user origin labels are therefore not valid fact
provenance. Catalog SHA fields keep their existing 64-character lowercase hex
representation. All new evidence digests are `sha256:` prefixed. Nanoseconds
are signed 64-bit values represented by canonical decimal strings. All four
coordinate fields are `null` for the explicit `not_applicable` and `unknown`
time bases. `not_applicable` is reserved for non-temporal metadata; `unknown`
means the producer emitted a temporal source record or event without a
timestamp. Such observations participate in `latest_per_revision` analysis,
while absolute and revision-end-relative historical analysis fails closed
rather than silently dropping or inventing a time for them.

Normalized revision timestamps are not presumed to be Unix time. A trusted
ingestion descriptor may declare `timeline_time_basis: absolute_unix_ns` or
`source_clock_ns`; source-clock declarations also require a bounded
`timeline_clock_domain`. If no basis is proven, the evidence projection uses
signed `revision_start_relative_ns` coordinates. Those declared/default
relative coordinates are already offsets and remain unchanged;
`timeline_start_ns` is a bound, never an origin that core subtracts. An
absolute private-analysis request fails closed for any selected revision
without an absolute declaration. Uncertainty participates in cutoff selection:
a possible-time interval that overlaps the cutoff is retained with its
uncertainty, while an interval wholly after it is excluded.

`plan_basis_revision_id` is an evidence-safe opaque projection. If the source
execution-plan basis is already a safe identifier it is retained; a structured
or path-shaped ingestion basis is replaced with a domain-separated SHA-256
token. The exact raw plan remains committed by `execution_plan_digest`, so the
projection neither weakens binding nor leaks a path-like source name.

An envelope contains exact fields `contract_version`, `reference`,
`disclosure_decision`, `payload`, and `envelope_digest`. The decision must be
allowed and match both the reference class and a domain-separated digest of
its tenant/project/workspace scope; a decision evaluated for one workspace
cannot be replayed into another. `never_assistant` is structurally rejected.
Payload is an exact strict-canonical JSON object with a 1 MiB UTF-8 limit, 16
container levels, 1,024 items per container, 4,096 value units, and 65,536
characters per atom. Payload JSON numbers are limited to the exact JavaScript
range; larger integers use canonical decimal strings. Envelope parsers reject
duplicate/missing/unknown fields and require, rather than mint, all wire
digests before verifying content, reference, and envelope identity.
Construction alone grants no access. The implemented trusted tool service
resolves these claims through tenant-scoped deployment adapters, requires an
independent catalog-binding validation, and evaluates disclosure before
materializing the payload and again before release.

Multi-node output uses several atomic reference digests. Mutable session IDs,
snapshot member IDs, topology contexts, route-trace IDs, and plug-in run IDs
are not citation identity.

The exported private-analysis request and advisory-output values are also
implemented as a library/local-wire contract. The authorized `/v1` lifecycle
does not expose these canonical wire values directly; it admits caller intent
and returns bounded projections. `PrivateAnalysisRequest` wire version 3 binds
the exact scope, a
canonical unique
vector of 1 to 128 revision bindings, selected runner ID/version/closed
transport/configuration digest, workspace policy digest, trusted instruction
profile digest, exact closed tool-catalog digest, closed task kind, untrusted
query, explicit clock selection, bounded limits, and the exact deployment-owned
`evidence_service_digest`. Its `request_digest`
covers every field. Time coordinates
are canonical decimal strings; `latest_per_revision` carries `null`.

Version 2 remains parseable only with the reserved legacy evidence-service
digest; current execution rejects it against every non-legacy registration so
a retained request cannot silently acquire a different evidence authority.

`PrivateAnalysisResult` is bound to the request digest. It contains one
support-labeled summary claim plus unique-ID detail claims/proposals; summary
cannot carry free-form uncited text and consumes one slot from the positive
`max_claims` budget. An `evidence_supported` claim requires
one or more unique canonically ordered citations; an
`unsupported_hypothesis` forbids citations. A citation contains only an
`EvidenceReference.reference_digest`. Every proposal has fixed provenance
`assistant_suggested`, at least one citation, a closed proposal kind, and a
bounded strict-canonical JSON object under a named payload schema.

`validate_private_analysis_result` requires the original request and the exact
set of references recorded as disclosed for that run. It rejects request,
scope, or revision mismatch; undisclosed or duplicate references; and output
that exceeds the request's claim, proposal, or byte limits. Construction or
wire parsing does not authorize a request and does not establish that a
reference was disclosed.

Failures use closed `stage`, `code`, and `retryable` combinations. Their human
message is selected locally from the code and is not serialized, preventing
runner exception text or paths from entering the wire value. A versioned
outcome contains exactly one result or one error. All nested values and the
outcome have required verified self-digests, exact field sets, strict JSON,
duplicate-member rejection, JSON-safe numeric bounds, and an 8 MiB overall
wire ceiling. The result ceiling reserves enough space for its required
outcome wrapper. Summary, claim, and proposal text remains private output and
is not implicitly safe for an untrusted client or log sink.

The library also exposes one exact, self-digested evidence-tool catalog with
only `query_evidence`, `read_evidence`, and `analyze_evidence`. Definitions contain closed metadata,
not executable handlers. Calls bind the request and catalog digest and require
the argument type declared for the selected tool. Query results expose only
unique, canonically ordered `EvidenceReference` values; read results expose one
matching disclosure-gated `EvidenceEnvelope`. Query paging is keyset-based.
Its typed cursor binds request, catalog, canonical query fingerprint,
immutable eligible-set snapshot digest, and last reference digest, preventing
cross-request, cross-filter, or changed-snapshot replay. Tool failures use a
closed static payload-free vocabulary. The analyze arguments bind one exact
node/revision, a closed intent, canonical parent-reference
digests, bounded JSON parameters, and an observation ceiling; they never carry
an evidence payload or executable provider. The trusted deployment resolves
the unique exact provider from that retained revision plan. Its result is one
derived evidence envelope whose provider, revision, argument digest, intent,
parents, observation schema, and citation subsets are validated. These values
perform no authorization, retrieval, disclosure evaluation or recording,
runner execution, or plug-in invocation by themselves.

Catalog/tool definition/binding/call/result/error wire contracts are version 2
after adding `analyze_evidence`; query and read argument/result versions remain
independently versioned. A durable run admitted against the former two-tool
catalog remains readable for audit but is not executable under the new catalog
digest; operators must resubmit it so admission binds the current catalog and
instruction profile. Core never silently substitutes a changed tool catalog.

`query_evidence` arguments v2 add an optional indexed inclusive-overlap time
window. `time_basis`, `time_start_ns`, and `time_end_ns` are all-null or all
present; source-clock windows also name `time_clock_domain`. The nanosecond
coordinates are canonical signed-64 decimal strings on the wire, not JSON
numbers. Unknown/not-applicable reference times do not match a bounded window,
and declared uncertainty expands the interval used for overlap.

The core library now also exports `PrivateAnalysisToolService`, a distinct
trusted interpreter for that inert catalog. One service instance is bound to
one detached `PrivateAnalysisRequest`, the shipped catalog digest, and a
runner policy whose transport matches the request. Each detached call must
bind the same request and catalog digests; duplicate call IDs fail as a runner
protocol error. The catalog definitions themselves remain value-only and gain
no executable handler.

Service composition keeps separate callbacks for exact-request
authorization, current scope-bound `PrivateAnalysisWorkspacePolicySnapshot`
resolution, candidate-reference query, exact reference lookup, trusted-catalog
binding validation, payload materialization, and optional plan-bound evidence
analysis. The model-visible analysis arguments contain no configured instance;
the trusted callback resolves the unique provider from the exact target
revision. It receives only parent envelopes already materialized in this
request. The core page-query and batch
validator extensions are explicit constructor adapters; legacy complete-query
and single-reference validator callbacks are never retried to infer arity.
The page-query callback has the exact shape
`(request, arguments, evidence_classes, cancellation_probe)`, where the last
value is a `Callable[[], bool] | None` cooperative cancellation/deadline probe.
Authorization decisions carry the request digest and a
domain-separated tenant/project/workspace scope digest. Authorization and
policy are checked for every call and again before release. The current policy
digest must equal the request's policy digest. Callback failures are contained
except for process-control exceptions and map to closed payload-free errors;
callback exception text is never returned.

A successful analysis result is revalidated as current v3
`plugin_capability_result` evidence with `plugin_analyzed` provenance, the
standard payload schema, exact argument digest/intent/parents, canonical
observation IDs, and citation subsets. It is committed to the request-local
ledger and materialized overlay atomically with byte/item accounting. Later
exact reads and analyses may consume that overlay; it is intentionally absent
from immutable query snapshots. Without the optional trusted analysis callback,
the tool returns `capability_unavailable`.

`ControlPlane` supplies that trusted callback for its core revision-evidence
service. Provider selection uses the exact retained plan and an unqualified
`EVIDENCE_ANALYSIS` selector, so the route must be unique. The callback passes
only already-materialized parents, omits plug-in diagnostics from the derived
payload, binds the exact provider pin into provenance, and caches one exact
result per canonical argument digest for the lifetime of the request service.

A core query callback supplies one bounded page from an immutable,
corpus-cached candidate snapshot. The service deep-detaches only that page,
requires unique digests and one valid batched catalog binding, and rechecks the
typed filters and disclosure policy. Foreign, conflicting, or ineligible page
values fail unavailable. Continuations keyset into the same membership digest
without reconstructing the complete candidate tuple while that snapshot is in
the corpus's bounded cache. A continuation whose exact snapshot has been
evicted fails closed as `cursor_invalid` before any membership rebuild; callers
must restart the query rather than assume indefinite cursor durability. It
also fails immediately when a cursorless rebuild of the same fingerprint is
already in flight; continuations never join or initiate replacement builds. The
separate legacy callback path retains the former bounded complete snapshot for
deployment compatibility.

Core checks the page-query probe before and after the provider call. The core
corpus additionally checks it while materializing indexed candidates,
filtering, sorting in bounded chunks, hashing immutable membership, and copying
the selected page. Same-query singleflight waiters use bounded timed waits and
probe outside the corpus lock. A cancelled waiter does not disturb producer
ownership; a cancelled producer clears ownership and wakes waiters without
publishing a partial cache value. Process-control exceptions propagate, while
probe failure, a non-boolean result, cancellation, or deadline expiry maps to
the static retryable `evidence_unavailable` result.

Successful query-page references enter the citation ledger even though no
payload was transferred. An exact read resolves separately; absent, foreign,
and disclosure-denied references all return `evidence_not_found`. Only an
eligible, catalog-valid reference reaches the payload materializer, and a
second authorization/policy check occurs before the envelope is released.

The service exposes detached `budget_state` and `disclosed_references`
snapshots. One lock atomically reserves unique call IDs and commits ledger and
byte-accounting updates. `max_tool_calls` counts admitted calls before provider
work. `max_evidence_items` counts unique reference digests disclosed by either
query or read. `max_evidence_bytes` is cumulative transfer accounting: query
pages charge each canonical reference's UTF-8 size and reads charge the
canonical envelope's UTF-8 size, including repeated transfers. A result that
would cross an item or byte ceiling returns `budget_exceeded` without a
partial ledger or byte update; its already admitted tool-call unit remains
consumed.

One pristine service may be claimed by exactly one
`PrivateAnalysisToolRunLease`. Lease acquisition is atomic with direct-call
admission and requires empty call, byte, and citation state. The lease exposes
the same closed tool execution plus a budget-neutral `require_run_access()`
check. Direct calls fail while it is open, release is permanent, and a service
cannot be silently reused for another runner execution. The first admitted
direct-call attempt permanently selects direct-call mode even when it returns
`budget_exceeded` before charging a call or fails authorization; zero counters
therefore do not make that service pristine again.

The core also implements a trusted local
`ConfiguredPrivateAnalysisInProcessRunner`; the runner object itself owns no
`/v1` route.
Construction binds an exact in-process runner ID, version, configuration
digest, and trusted instruction-profile digest. Execution accepts one exact
fresh leased service. It requires current authorization and pinned workspace
policy before invoking the callback, supplies only detached request/catalog
values and a thread-affine canonical-call gateway, closes that gateway, and
then rechecks access before accepting output.

The operator callback is called once and returns strict canonical
`PrivateAnalysisResult` JSON. Every tool-call JSON document is parsed through
the existing bounded contract and every response is detached before returning
to the callback. Malformed, duplicate, recursive, cross-thread, concurrent,
or post-close calls latch `runner_protocol_error`; catching the local abort
does not clear that state. The gateway permits at most `max_tool_calls + 1`
recorded exchanges, where the extra response can report exhaustion. Its
constant-memory transcript binds only call/response digests and the final
outcome, ledger digest, and counters; it retains no payload or model text.
Exchange counts, chain state, and terminal state are not callback-visible
properties; core takes one private atomic snapshot only after owner-thread
close. Callback-visible execution, deadline, and close operations are
owner-thread-affine.

After a final access check, core snapshots the disclosure ledger, applies the
request's canonical output-byte, claim, and proposal ceilings, and calls
`validate_private_analysis_result`. The callback-owned value is never returned
directly. Non-process callback failures become static `runner_failed`; exact
process-control signals propagate. Measured monotonic deadline expiry becomes
`timeout`, including a callback result returned late or one that crosses the
deadline during result parsing, budget enforcement, or citation validation.
When an authorization, policy, tool, or protocol operation itself crosses the
deadline, `timeout` takes precedence over the otherwise applicable static
error from that late operation.
The in-process callback cannot be forcibly preempted, so a callback that never
returns can still block the host.

This transport is a validation and supported-interface boundary, not a Python
sandbox. The configured callback is process-trusted. Core adds no filesystem,
network, shell, plug-in, database, mutation, retry, persistence, HTTP, or
promotion authority through the callback's supported interface and ships no
provider SDK, endpoint/key setting, or public-network fallback. Because Python
reflection can reach any in-process object's private implementation graph, a
callback that deliberately reads or mutates private gateway state is outside
this trusted transport's contract; it must use the implemented local-child
transport when that threat exists. Unsupported private-state bypass is not an
evidence API and finalization fails it closed with a static protocol error when
detected.
The resulting payload-free transcript keeps the real last-complete disclosure
ledger and budget. Calls that reached the private lease without a gateway hash
chain entry are counted by `unattributed_tool_call_count`; they are not rewritten
as a zero-use run.
Both configured runners expose a transport-neutral, payload-free
`PrivateAnalysisTranscriptSummary`. Their accounting snapshots also accept an
optional observer that receives the complete detached reference ledger and
budget after every tool operation. The observer must return successfully
before the local snapshot is published and before that tool response reaches
the model. These two hooks let the adjacent durable run store enforce
write-ahead disclosure accounting without giving either transport database
authority. The separate authenticated lifecycle facade composes those hooks;
human review and promotion use the separate implemented proposal-review
contract and never extend the runner's authority.

An in-process registration owns a detached runner clone plus a bounded seal of
the exact retained callback. The seal covers source-backed code, statically
resolved imports and globals, defaults, ordinary closures, function-owned
executable state, and callable class/instance behavior. Frozen dataclass and
canonical container configuration bind by value. A native synchronization or
similar retained capability outside the callback's source scope binds by exact
same-process identity and native type/code provenance; its volatile lock/event
state is deliberately not configuration. Replacing that capability changes
the seal. Core recomputes the seal immediately before invocation, then repeats
access, deadline, and cancellation checks. Callback-slot, closure, instance,
class, or executable-state drift yields `runner_unavailable` without invoking
the callback. Detached registrations share the original runner's execution
gate, so cloning cannot create concurrent callback authority.

The local-child library boundary is implemented by
`ConfiguredPrivateAnalysisSubprocessRunner`; the runner object itself owns no
`/v1`, CLI, or UI model-run surface. Construction requires a `local_subprocess` selection and
an exact equality between its configuration digest and the sealed launch
configuration. The request must equal that runner selection and bind the same
instruction-profile and shipped tool-catalog digests. A runner-selection
mismatch produces runner-stage `runner_unavailable`; instruction or catalog
binding mismatch produces request-validation `invalid_request`. No child is
started for either failure.

`PrivateAnalysisSubprocessLaunchConfiguration` is an exact, frozen v2 launch
value, not an ambient-process overlay. `argv` MUST be a built-in tuple of 1 to
128 nonempty scalar strings, each at most 32,768 UTF-8 bytes and containing no
NUL or control character. `argv[0]` MUST be absolute; `.bat` and `.cmd` are
forbidden; and `subprocess.list2cmdline(argv)` MUST fit 30,000 UTF-16 units. The
working directory MUST be an absolute scalar string of at most 16,384 UTF-8
bytes. On Windows, no executable or working-directory path component may end
in a period or space; this validation precedes normalized executable-name
`.bat`/`.cmd` rejection so Win32 normalization cannot change the sealed
effective path. The environment MUST be a built-in tuple of at most 256 built-in
two-string tuples. Names MUST match `[A-Za-z_][A-Za-z0-9_]{0,127}`, be unique
case-insensitively, and are sorted for sealing. Values may be empty but contain
no controls and are limited to 65,536 UTF-8 bytes; encoded names and values
together are limited to 256 KiB. Stderr admission is 1 through 256 KiB, and
terminate and kill grace values are independently 10 through 10,000 ms.

The actual executable and up to 128 ordered `helper_artifacts` MUST be regular
files with canonical absolute paths. Core seals path, type/size metadata, and
content, bounded to 512 MiB per artifact and 1 GiB total. Every argv operand
that resolves to a regular file, including `--name=/path`, MUST name one of
those helpers unless its unique argv index is declared in
`runtime_data_argument_indices`; every non-option operand obeys the same rule.
A runtime-data argument MUST NOT identify, import, or load executable code and
MUST NOT simultaneously name an attested helper. Exact `-c` and `-m` dynamic
code forms are forbidden regardless of executable filename. Core rechecks
coverage after hashing and immediately before launch, and rehashing polls the
same cancellation and absolute deadline. Newly appearing files,
canonical-path changes, or metadata/content drift fail before `Popen`.

The launch self digest covers the exact argv, cwd, sorted complete environment,
adapter-identity digest, executable-artifact digest, ordered helper paths/count,
runtime-data indices, stderr limit, both reap graces, and literal
`descendant_policy: forbidden`. The adapter-identity digest remains the
deployment's semantic binding; core independently authenticates the actual
executable and declared helper bytes. Raw paths and bytes do not enter durable
state, wire projections, or representations. Core supplies `list(argv)`, the absolute `executable`, `shell=False`,
binary unbuffered pipes, exact cwd, `env=dict(environment)`, `close_fds=True`,
and `start_new_session=False`; Windows additionally uses `CREATE_NO_WINDOW`
when present. Therefore the child receives no ambient-environment merge, shell
expansion, or `PATH` executable lookup.

Protocol version
`router_dump_analyzer.private_analysis.local_subprocess_protocol.v1` admits
only exact message objects with fields `contract_version`, `run_digest`,
`sequence`, `kind`, `payload`, and `message_digest`. `message_digest` is the
`sha256:` digest of the strict-canonical object containing the other five
fields. `run_digest` binds the request, shipped catalog, instruction profile,
runner configuration, launch configuration, and a `local_subprocess_run`
domain. Sequence is a nonnegative JSON-safe integer. The closed kinds are
`hello`, `ready`, `start`, `tool_call`, `tool_result`, `tool_error`,
`analysis_result`, and `runner_failure`; the last kind contains only closed
reason `unavailable` or `failed`.

`hello` and `ready` payloads MUST be `{}`. `start` MUST contain exactly object
members `request` and `tool_catalog`. Each tool or result payload MUST contain
exactly its same-named object (`tool_call`, `tool_result`, `tool_error`, or
`analysis_result`); the transport deep-detaches and bounds that object but
leaves its typed interpretation to the existing nested contract. Payload is
limited to 8 MiB, 20 container levels, 1,024 items per container, 2,000,000
value units, 1,048,576 characters per atom, and JSON-safe integers. The total
frame adds a 64 KiB envelope allowance.

Encoding is the strict canonical UTF-8 JSON envelope followed by exactly one
LF byte. Decoding accepts exact `bytes` containing exactly one complete frame
and rejects an empty body, missing or multiple LF, every CR/CRLF, leading UTF-8
BOM, invalid UTF-8, duplicate object members, `NaN` or infinity, non-object
root, noncanonical serialization, oversized data, unknown or missing fields,
unsupported kinds/reasons/versions, and invalid or mismatched digests.

The state machine is one lockstep, same-run global sequence:

1. parent sends `HELLO 0 {}`; no request or catalog has been disclosed;
2. child MUST answer `READY 1 {}`;
3. core re-runs live authorization and pinned-policy admission;
4. parent sends `START 2 {request, tool_catalog}`; and
5. the child sends `TOOL_CALL` or a terminal message at sequence 3, with every
   later message in either direction incrementing exactly one.

A typed child tool call is executed only through the exclusive run lease and
receives the next-sequence `TOOL_RESULT` or `TOOL_ERROR`. After one
`budget_exceeded` tool error, another tool call terminates the run as
`budget_exceeded`. Core checks the monotonic deadline before and after lease
admission, after typed call parsing but before provider entry, and after the
provider returns; an expired call never begins provider work. The only terminal child kinds are `ANALYSIS_RESULT` and
`RUNNER_FAILURE`. After either, core closes stdin; the next stdout read MUST be
EOF, not another frame; the direct child MUST then exit zero before the same
monotonic request deadline; and live access MUST pass once more. Only then may
the failure reason be mapped or the result be parsed, budget-checked, and
citation-validated.

Launch `OSError`, selection mismatch, or child failure reason `unavailable`
maps to `runner_unavailable`. Generic launch/runtime failure, premature EOF,
stdio failure, admitted-stderr overflow, nonzero exit, child reason `failed`,
or failed direct-child/helper cleanup maps to `runner_failed`. Invalid frame,
digest, sequence, kind, typed tool call, trailing post-terminal frame, or
transcript integrity maps to `runner_protocol_error`. Deadline expiry while
waiting for a frame, final EOF, exit, access, cleanup completion, result
validation, or final outcome/transcript/receipt attestation maps to `timeout`
and takes precedence over every non-timeout outcome after the late operation.
Malformed final output maps to output-validation `invalid_result`; output,
claim, or proposal ceilings map to `budget_exceeded`. Existing closed
tool-service errors are detached and preserved. These error wires remain
payload-free and never serialize child stderr or exception/path diagnostics.

Two non-daemon threads drain protocol stdio and stderr concurrently. Stderr
content is discarded; only its admitted byte count is retained. Cleanup runs
in `finally`, signals the pump, applies bounded terminate-then-kill waits while
the direct child remains live, closes stdin/stdout, and preserves stderr until
its helper drains buffered bytes to EOF after child exit. A still-live child
has stderr closed to unblock the helper. Both helpers are bounded-joined before
sealing. Failure to observe child exit and stopped helpers withholds the
receipt and keeps the durable cleanup fence active. The coordinator retains
the exact session/process handle and unpersisted release capability for bounded
retry; only confirmed cleanup reseals and releases the receipt. No PID is
persisted or reconstructed. This is a fail-closed terminal condition, not an
unconditional OS reaping guarantee, and it covers the direct child only.
Adapter-created descendants are contractually
forbidden because the portable implementation has no Windows Job Object or
equivalent process-tree reaper.
Ordinary cleanup, snapshot, or lease-close exceptions are contained as
`runner_failed`; a pending process-control exception is preserved across those
best-effort finalizers.

`PrivateAnalysisSubprocessTranscript` is a payload-free self-digested seal. It
binds request, catalog, instruction-profile, runner-configuration,
launch-configuration and run digests; message/tool-call counts; admitted
metadata and stderr byte counts; message-chain, evidence-ledger and outcome
digests; and the final tool-budget snapshot. Each message-chain link contains
only direction, sequence, kind, message digest, and frame size. It retains no
argv/environment value, request/query, evidence/tool payload, model output,
stderr text, exception, path, or timestamp. Its detached execution receipt is
not returned by an HTTP API in this stage; the receipt's transport-neutral
summary is the value accepted by the separate durable run store.

The subprocess runner is a killable direct-child fault boundary, not an OS
sandbox. The peer is untrusted at the JSONL boundary and cannot receive Python
objects through its supported interface, unlike the deployment-trusted,
unsandboxed in-process callback. It nevertheless inherits the host user's
filesystem and network authority and receives no core CPU/memory quota;
deployment containment must remove those capabilities and enforce the
no-descendants policy when required. Neither runner is wired to public model
APIs, a provider SDK, endpoint/API-key settings, network fallback, product
configuration, model-run HTTP scheduling, automatic retry, annotation
mutation, or promotion.

### Local private-analysis run-store API

`SqlitePrivateAnalysisRunStore` is a local library API, not an HTTP or CLI
surface. It persists the exact canonical `PrivateAnalysisRequest`, its ordered
multi-revision vector, write-ahead evidence ledger and budget, a payload-free
transport summary, and a sealed terminal outcome. Its lifecycle vocabulary is
closed to `queued`, `running`, `cancel_requested`, `completed`, and
`cancelled`.

Admission uses `create_run(request, idempotency_key, actor_id, now_ns=...)`.
The `ControlPlane` composition supplies a catalog validator and holds the same
single-host file fence used by catalog retention while it re-derives every
workspace, fixture, revision, identity, and immutable execution-plan binding
and inserts the run. A standalone store must supply equivalent atomicity when
its catalog can change concurrently. Scope-bound reads are `get_run` and the
bounded keyset `list_runs`.

Execution is fenced and optimistic-versioned. `claim_run` returns one opaque
execution ID and bounded lease; `renew_lease` and `commit_accounting` require
that identity, the expected record version, and an unexpired lease.
`commit_accounting` accepts only an append-only reference set and monotonic
budget counters within the exact request ceilings. `request_cancellation`
completes a queued run immediately and marks a running run cooperatively.
`complete_run` accepts a terminal result only when its request, outcome,
ledger, budget, catalog, instruction, runner, and transcript commitments equal
the persisted values. A successful result is also revalidated against the
exact durable ledger and request-specific output, claim, and proposal limits.
Once cancellation wins the version race, an ordinary result cannot overwrite
it. `recover_expired_runs` never retries: an expired attempt becomes static
`runner_failed`, or `cancelled` when cancellation was already requested. The
store excludes every run with a durable evidence-factory or local
model-adapter cleanup fence; it never turns lease expiry into a terminal claim
while child death is unconfirmed.

Each transition appends one contiguous, predecessor-sealed, payload-free audit
entry. `list_audit` reconstructs and verifies that chain against the redundant
run head. A run has at most 10,000 audit entries, with capacity reserved for
cancellation and terminalization. `referenced_revision_ids` returns all
revisions protected from catalog retention by retained runs. Run retention is
disabled by default;
`inventory_retention`, `run_retention`, and `list_retention_journal` are
bounded library operations. Execution purges only terminal proprietary run
rows and preserves a payload-free tombstone and self-digested journal. Active
heads have independent guard and live-admission anchors; paired loss therefore
still fails catalog protection closed, and admission caps one scope at 10,000 active runs. Purge
uses secure deletion and a truncating WAL checkpoint before reporting
completion. It deliberately does not run a full-database `VACUUM`; optional
freelist page reclamation is offline maintenance. An already committed journal
makes a failed checkpoint safe to retry.

The dedicated SQLite database contains proprietary requests and successful
outcomes at rest, including in its active WAL and every pre-purge backup or
storage-layer copy. `ControlPlane` binds its opaque installation identity to a
root initialization record and refuses a missing binding, missing/truncated database, or replacement
database after first initialization. Deployments must protect the state
directory and backups and use disk encryption appropriate to the selected
disclosure mode. This storage API adds no provider SDK, public-network
fallback, automatic retry, annotation mutation, or proposal promotion. The
separate application facade below is the only HTTP owner of its run lifecycle.

### Local private-analysis execution API

`PrivateAnalysisExecutionCoordinator` is also a local library API; it is not a
web route, scheduler, provider adapter, or CLI. A
`PrivateAnalysisRunnerRegistration` binds one exact configured in-process or
local-subprocess runner to exactly one evidence mode: a deployment-owned
`tool_service_process_factory`, a compatibility-only
`trusted_inline_tool_service_factory`, or a `core_revision_evidence_policy`.
The latter asks the owning `ControlPlane` to freeze the request's exact
revision set into its indexed normalized-evidence corpus. A standalone
coordinator has no catalog authority and therefore rejects core-evidence
registrations unless its composition root supplies the core factory.
Resolution uses the full `PrivateAnalysisRunnerSelection` plus the sealed
instruction-profile digest. Duplicate registrations and all fallback routing
are rejected.

`execute_run(scope, run_id, expected_version, actor_id, execution_id=...)`
executes one already-admitted queued record. It claims before constructing the
request-bound service, rejects both visible and zero-counter lifetime reuse,
maintains the lease, commits each new complete
ledger/budget snapshot before response release, and seals the exact runner
receipt. A factory or service-binding failure after claim uses
`finalize_unstarted_attempt`: it is permitted only with the exact live fence
and zero accounting, produces a static error, and stores no invented
transcript. An absent runner/profile leaves the record queued. No path retries
the model automatically.

`PrivateAnalysisToolServiceProcessFactory(target, configuration_json="{}")`
requires a module-level `PACKAGE:ATTRIBUTE` and a canonical JSON object no
larger than 64 KiB. The spawned target receives only the detached request and
detached decoded configuration and MUST return an exact pristine
`PrivateAnalysisToolService`. Core passes no live callable or pickle payload.
The fixed child retains the service; the parent admits only the exact
core-owned local/remote service union and uses a closed, canonical, byte-bounded
IPC protocol with one in-flight call. The parent verifies every result/error,
request binding, sequence, complete append-only reference ledger, and monotonic
budget snapshot before release. The effective `evidence_service_digest` binds
the target, configuration digest, and supplied semantic digest; configuration
bytes are not stored in the run. Factory preparation shares the run's absolute
deadline, polls durable cancellation, and completes terminate/kill/join cleanup
before a static `timeout`, `cancelled`, or `runner_failed` unstarted outcome is
sealed. The target identity covers exact static import provenance, bounded
module/package bytes, source-declared recursive bytecode and signature/default
state, live class methods, and recursively verifiable globals/static attributes
and statically resolvable local imports across package boundaries.
Function-owned executable state participates in the same traversal. Callable instances also bind bounded canonical
`__dict__`/slot and ordinary class state. Fingerprinting never executes local
imports merely to discover authority; referenced imports must already be
loaded by deterministic package initialization. Local-import source is
lexically preflighted against the remaining node budget before AST
construction. One traversal is capped at 64 value
levels, 32,768 value nodes, 2,048 code objects, and 32 MiB of runtime values;
generated code, unsafe closures, custom builtins, and unsupported mutable or
opaque state are rejected. Frozen dataclass and enum constants are bounded and
bound by value. Retained live class and mutable-object snapshots are rechecked
after traversal before the identity is returned.
Child diagnostics and process-control tracebacks are not returned.
Proxy `close()` remains retryable until the child is confirmed dead and is
idempotent only after successful reap. The local model-adapter runner applies
the same rule to its direct child and helper threads. A cleanup failure
surfaces as a static execution-unavailable infrastructure error and MUST NOT
seal the run or release a receipt. Core creates a separate cleanup-fence row
before either launch, keyed by scope, run, and execution. It stores a
domain-separated SHA-256 verifier,
creation/last-attempt times, and a bounded attempt counter, but no PID, release
capability, command, path, or payload. The random 256-bit capability remains
only with the live process owner and is not returned by `get_cleanup_fence` or
`list_cleanup_fences`.
`complete_run`, `finalize_unstarted_attempt`, and generic expiry recovery all
fail closed while that row exists. The original coordinator retains the exact
live process, session, or bootstrap-cleanup owner and may perform one bounded
retry per explicit recovery/shutdown pass. Only confirmed reap followed by
verification of the unpersisted capability releases terminal recovery; a
withheld receipt is resealed only at that point. A restarted coordinator has no such
process authority or release credential, does not kill from guessed/persisted
identity, and leaves the fence available through bounded
`get_cleanup_fence`/`list_cleanup_fences` diagnostics. An interruption while
clearing the durable row likewise retains the in-memory release capability and
idempotent cleanup owner for a later retry.
The ordinary run projection exposes only `cleanup_pending: true|false`;
execution identity and retry timestamps remain local store diagnostics, while
the verifier and release capability are not exposed at all.

The trusted-inline compatibility field has no hard preemption guarantee. Its
callable must return and poll any deployment-owned cooperative cancellation;
it is not described as deadline-bounded because Python threads cannot be
safely cancelled.

The execution gate belongs to the configured runner instance rather than a
coordinator registration, so two coordinators sharing one runner cannot enter
it concurrently. A completion that encounters an already-terminal record is
idempotent only when the store validates the exact same execution receipt;
conflicting expiry recovery or terminal output raises a conflict.

`request_cancellation` first commits the durable one-way state change and only
then signals a matching local attempt. Other coordinator processes observe it
through polling. An immediate durable refresh after local attempt registration
prevents the claim/registration race from consuming a service. An accounting
observer that discovers cancellation commits and publishes the same complete
snapshot before the following cancellation probe unwinds. In-process
cancellation is cooperative; local-subprocess
cancellation terminates and reaps the direct child and helper threads before a
cancelled receipt is accepted. A cancellation between receipt creation and
completion re-seals that same transcript, ledger, and budget against the
cancelled outcome. Cleanup without attestation remains a runner failure and is
left for expiry recovery.

The control-plane core adapter revalidates every workspace, fixture, revision,
dataset, execution plan, and current policy before runner entry. It resolves
each revision's clock independently, excludes future records, applies half-open
historical intervals, and indexes the frozen corpus by scope, revision, kind,
node, producer, and subject. Generic projections use existing client redaction;
when both workspace and runner grant full fidelity, plug-in-owned normalized
and retained-source fields are instead proprietary evidence. The configured
corpus ceiling is at most two million entries and has an independent
canonical-payload ceiling (512 MiB by default, 2 GiB hard maximum).
Construction observes cancellation/deadline checkpoints during chunked reads,
array validation, client-safe descriptor/resource redaction-policy scans,
projection, deterministic chunked active-resource ordering, and bounded-chunk
index sorting. Per-record checks bracket normalization, payload hashing,
reference construction, and immutable payload freezing. Checks bracket the
byte-bounded standard-library UTF-8 decode and `json.loads` calls, which are not preemptible
mid-call. The same request-bound probe remains attached to the core page-query
service after construction, including bounded singleflight waits and snapshot
filter/sort/hash work. Tool snapshot and page limits remain smaller.

`PrivateAnalysisExecutionLimits` bounds concurrent local runs, lease duration,
heartbeat cadence, cancellation polling, and monitor joining. `close(timeout)`
stops admission and waits for active calls and monitors; it never pretends to
preempt a non-cooperative trusted callback. `ControlPlane` owns one coordinator
whose registration set is empty unless deployment composition explicitly
supplies approved local runners.

### Authorized private-analysis run HTTP API

These routes are relative to
`/v1/control-plane/projects/{project_id}/workspaces/{workspace_id}`:

| Method | Path | Contract |
|---|---|---|
| `GET` | `/private-analysis-capabilities` | Core-owned task, limit, transport, state, and action descriptors; `control-plane:read`. |
| `GET` | `/private-analysis-runners` | Policy-filtered detached runner identities; `control-plane:read`. |
| `POST` | `/private-analysis-runs` | Derive and admit one queued request; `control-plane:write` and `Idempotency-Key`. |
| `GET` | `/private-analysis-runs` | Bounded `(created_at_ns, run_id)` keyset page; `control-plane:read`. |
| `GET` | `/private-analysis-runs/{run_id}` | One run summary with a strong numeric `ETag`. |
| `POST` | `/private-analysis-runs/{run_id}/execute` | Synchronously wait for one fenced local execution; `control-plane:write` and strong numeric `If-Match`. |
| `POST` | `/private-analysis-runs/{run_id}/cancel` | Durably request cancellation before local signalling; `control-plane:write` and strong numeric `If-Match`. |
| `GET` | `/private-analysis-runs/{run_id}/report` | Display-safe terminal query/outcome projection plus `ETag`; conflicts while nonterminal. |
| `POST` | `/private-analysis-runs/{run_id}/proposals/{proposal_id}/decision` | Reject or explicitly promote one exact proposal; `control-plane:write`, current run `If-Match`, and `Idempotency-Key`. |
| `GET` | `/private-analysis-runs/{run_id}/proposal-decisions` | Bounded `limit`/`offset` page of durable human decisions; `control-plane:read`. |
| `GET` | `/private-analysis-runs/{run_id}/proposal-decisions/{decision_id}` | One exact decision plus its strong numeric `ETag`; `control-plane:read`. |
| `POST` | `/private-analysis-runs/{run_id}/proposal-decisions/{decision_id}/recover` | Explicitly resume one pending promotion from its retained human target; `control-plane:write` and decision `If-Match`. |

Create accepts this closed caller-intent shape; `limits` is optional and every
listed nested object rejects unknown fields:

```json
{
  "revision_ids": ["revision-a", "revision-b"],
  "runner": {
    "runner_id": "approved-local-model",
    "runner_version": "1"
  },
  "task_kind": "route_trace_analysis",
  "query": "Explain the asymmetric reachability.",
  "clock": {
    "mode": "absolute_unix_ns",
    "selected_time_ns": "1759686025000000000"
  },
  "limits": {
    "max_tool_calls": 32,
    "max_evidence_items": 256,
    "max_evidence_bytes": 8388608,
    "max_output_bytes": 1048576,
    "max_claims": 128,
    "max_proposals": 64,
    "deadline_ms": 120000
  }
}
```

Caller revision order is canonicalized before the service builds the immutable
binding vector. `task_kind` is one of `lttng_analysis`,
`resource_correlation`, `cross_node_corroboration`, `route_trace_analysis`, or
`general_evidence_review`. Clock `mode` is `latest_per_revision` (with no
selected time), `absolute_unix_ns` (non-negative selected time), or
`revision_end_relative_ns` (signed selected time). Queries are non-empty and
bounded to 32,768 characters and 131,072 UTF-8 bytes.

Omitted limits use `PrivateAnalysisLimits` defaults: 10,000 evidence items,
64 MiB evidence, 256 tool calls, 4 MiB output, 128 claims, 64 proposals, and a
300,000 ms deadline. The deployment may configure lower ceilings; a request
cannot raise them. The closed contract maxima remain an additional hard bound.

Capability discovery returns contract
`router_dump_analyzer.private_analysis.capabilities.v1`, the resolved scope,
an `enabled` boolean, and five ordered descriptor arrays: `capabilities`
(closed task-kind IDs, labels, and descriptions), `limits` (ID, label, unit,
minimum, and current deployment maximum), `transports` (the current workspace
policy intersection), `states` (including `terminal`), and `actions` (method,
abstract resource, ETag requirement, and eligible states). It is a scoped
`control-plane:read` response with `Cache-Control: no-store` and no resource
ETag. It never advertises registered-runner configuration, a model/provider,
an endpoint/key, or plug-in-specific capability fields; runner discovery
remains the separate endpoint below.

Tenant, principal, actor, policy digest, transport, configuration digest,
instruction-profile digest, tool-catalog digest, execution ID, and run ID are
not request-body authority. Core derives scope from the authorized path,
reconstructs canonical revision bindings from the catalog, reads the current
workspace policy, and resolves one exact deployment registration. Disabled
policy, disallowed transport, planless/cross-workspace revisions, unknown
runner, or deployment-ceiling violations fail before persistence or execution.
Execute checks the supplied run version before policy evaluation, then re-reads
the current workspace policy before claiming a nonterminal run. The request-
bound tool service remains the final race-safe policy gate before evidence is
disclosed. A terminal execute replay also requires its current ETag; stale
terminal validators do not bypass optimistic concurrency.

Run summaries deliberately omit the query, evidence payloads, disclosed
references, transcript, execution/lease identifiers, callback values, and
audit internals. They include only detached lifecycle/request identity,
payload-free accounting, digests, and timestamps. Nanosecond fields and run
versions cross JSON as canonical decimal strings; the ETag is the same numeric
version. Every response is `Cache-Control: no-store`. List cursors require both
`after_created_at_ns` and `after_run_id`; the response returns the same pair as
`next_cursor` only when another page may exist.

Runner discovery returns `{"items": [...]}`. Each item contains only
`runner_id`, `runner_version`, closed local `transport`, `configuration_digest`,
`instruction_profile_digest`, and `evidence_service_digest`; it exposes no
callable or tool-service
factory. A disabled workspace policy, an empty registration set, or no
transport intersection returns an empty list. Run-list responses are
`{"items": [run-view...], "next_cursor": object-or-null}` ordered ascending by
`(created_at_ns, run_id)`, with default page size 100 and maximum 1,000. A run
view contains `scope`, `run_id`, state/terminal/version/request identity,
task/revision/node/runner identity, derived digests, clock, limits,
payload-free budget and ledger digest, exact evidence-service digest, outcome
digest, and lifecycle times.

The report is available only for a terminal run and has
`display_contract: router_dump_analyzer.private_analysis.display.v1`. It adds
the original query, an advisory-outcome display projection, and
`evidence_references`, after making unsafe or ambiguous display characters
explicit. `evidence_references` is ordered by reference digest and is exactly
the set of evidence-reference digests cited by the outcome's summary, claims,
and proposals. Core resolves each item only from that run's stored disclosed
reference ledger and fails closed if the ledger count/digest, uniqueness,
scope/revision binding, or a citation does not agree. Each item contains only
the reference digest; revision/node IDs; generic producer authority/ID and an
optional plug-in binding; evidence kind, subject kind, class, payload-schema
name, fact provenance, and time-range metadata. It never includes an evidence
payload, locator/path, locator digest, raw content digest, fixture/plan
identity, or an uncited ledger reference. This display projection is not the
canonical outcome wire JSON and must not be used as digest-verification input.
It does not grant annotation mutation
or proposal promotion by itself; the separate proposal-review mutation below
accepts a new human decision and revalidates the canonical terminal state.
Stable failures use `422` for invalid intent, `403` for
policy denial, concealed `404` for inaccessible scope/run, `409` for stale or
nonterminal state, `428` for missing preconditions, and `503` for unavailable
runner/service. Execution has no automatic retry or runner/transport fallback.
The serialized display report is capped at 64 MiB; an oversized projection
fails closed as service unavailable. `Cache-Control: no-store` is set on every
successful lifecycle response.

#### Proposal-review request and receipt

The terminal report remains read-only advisory data. A proposal mutation
re-opens that exact terminal report server-side and verifies the current run
version, result digest, proposal ID, and proposal digest before reserving one
durable human decision. The authenticated principal is the author; no body
field can override it. One scoped run/proposal pair has at most one decision,
and an idempotency key can replay only the identical canonical request. Its
stored receipt must reference that request's deterministic, authenticated
decision; redirecting it to another valid decision fails closed.

The request is a closed object with exactly these top-level fields (the
optional `rationale` and `target` may be omitted):

```json
{
  "proposal_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "result_digest": "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
  "disposition": "promote",
  "rationale": "Reviewed against the cited events.",
  "target": {
    "kind": "annotation",
    "annotation_kind": "note",
    "subjects": [
      {
        "revision_id": "revision-a",
        "kind": "event",
        "subject_id": "event-42",
        "node_id": "node-a",
        "start_ns": "1759686025000000000"
      }
    ],
    "title": "Human-confirmed failover",
    "body": "The cited event and reconstructed state agree.",
    "tags": ["reviewed"]
  }
}
```

`disposition` is `promote` or `reject`. Rejection requires no target and
rejects any supplied target. Promotion requires a separately human-authored
target; the model proposal payload is never interpreted as that target.
Annotation targets use `kind: annotation`, `annotation_kind` of `marker`,
`note`, or `tag`, one or more existing review subjects, and optional
title/body/tags. Manual-correlation targets use
`kind: manual_event_correlation`, subjects, edges with subject ordinals and a
link type, and optional rationale/tags/confidence. Only an
`event_correlation` proposal may create a manual event correlation. All
subjects must belong to revisions pinned by the reviewed run and must resolve
to an existing subject at that exact revision. Subject `start_ns`/`end_ns`
values are canonical non-negative signed-64 decimal strings.

The response contract is
`router_dump_analyzer.private_analysis.proposal_review.v1` and includes the
scope, decision/run/proposal IDs, proposal/result/request digests, pinned run
version, disposition, state, actor, rationale, target kind/ID, creation/update
times, and decision version. All versions and nanosecond values are decimal
strings. The decision version is also the strong ETag. A rejection is
immediately `completed` and writes no overlay. A promotion may be `pending`
between durable reservation and overlay completion; its deterministic overlay
is authored by the human reviewer, tagged `assistant-promoted`, and created
through the existing annotation/correlation idempotency boundary.

Admission requires the named run to be terminal with `cleanup_pending: false`.
The service resolves every target subject while holding the shared
proposal/review/catalog mutation fence, before creating any decision or
idempotency row. Repeating the original decision POST returns the existing
receipt but never resumes a pending promotion.
The idempotency receipt's request digest and decision ID must both match the
deterministic candidate, and the referenced decision is authenticated before
return.

The request digest commits to the exact tenant/project/workspace scope as well
as the reviewed run, proposal, result, human intent, and target. Decision and
promotion-target IDs are separate domain-separated deterministic projections
of that digest. Every materialized decision is authenticated before an ID or
its derived overlay idempotency key is used. Retention authenticates the
complete decision table before applying scope or lifecycle classification, so
moving a row between scopes or changing either generated ID fails closed.
The SQLite row additionally stores an HMAC-SHA-256 reservation attestation over
the scope, request digest, disposition, generated IDs, overlay key, and current
lifecycle state/version/timestamps. Completion updates lifecycle and
attestation in one transaction. An altered scope or state therefore cannot
evade retention protection. The
32-byte MAC key is a required `SqliteProposalReviewStore` constructor input and
is never stored in that database. `ControlPlane` owns an external, exclusively
created key file and refuses to replace a missing key for any pre-existing
decision database, including a schema-bearing database with no current
decisions. Legacy adoption requires an explicit migration. Consequently a
coherent rewrite of all unkeyed columns cannot mint a new recovery authority.

List/detail GETs are non-mutating and never resume pending work. Recovery is a
separate explicit POST with the current decision ETag. It verifies that the
canonical retained target still produces the original human request digest,
re-resolves its subjects, and idempotently completes the existing target rather
than asking the caller or model to reconstruct it. If an overlay commit
survived but its idempotency receipt did not, recovery continues only for the
exact live version-1 target with the retained actor and complete content.
Pending decisions block retention of their overlay receipts and referenced
catalog revisions. An already completed recovery is an idempotent read of the
same decision. All successful responses are `Cache-Control: no-store`; normal
concealed scope, validation, conflict, precondition, and unavailable-service
mappings apply.

### Local private-analysis deployment and CLI adapter

Private-analysis execution is disabled by default. `router-dump-server` and
the embedded analyzer accept the optional
`--private-analysis-deployment-module PACKAGE:ATTRIBUTE`; the latter requires
`--control-plane-dir`. The process-trusted target must be an exact frozen
`PrivateAnalysisDeployment`, or a callable returning one after receiving one
frozen `PrivateAnalysisDeploymentContext` whose only field is the canonical
absolute state directory. The descriptor carries 1..256 exact local runner
registrations, optional `PrivateAnalysisExecutionLimits`, and optional
`PrivateAnalysisDeploymentCeilings`. Public runner ID/version pairs are
unique. The loader invokes a factory once, detaches its result, preserves
process-control exceptions, and maps every other load/extension failure to a
static error. It is not a sandbox and is unrelated to device plug-in
selection.

`router-dump-private-analysis` exposes the same application lifecycle without
HTTP. Its global contract requires exactly one repeatable `--plugin` or
`--plugin-module` family, or one trusted `--plugin-deployment-module`; plus
`--state-dir`, `--tenant`, `--project`,
`--workspace`, and the deployment target; `--output` and `--pretty` are
optional. It opens existing scope and policy state and starts neither a web
server nor ingestion workers.

| Subcommand | Required operation fields |
|---|---|
| `runners` | none beyond the global scope/composition fields |
| `create` | `--request`, `--actor`, `--idempotency-key`; optional `--run-id` |
| `get` | `--run-id` |
| `list` | optional bounded `--limit`; paired `--after-created-at-ns` and `--after-run-id` |
| `execute` | `--run-id`, `--actor`, `--expected-version`; optional `--execution-id` |
| `cancel` | `--run-id`, `--actor`, `--expected-version` |
| `recover-expired` | `--actor`; optional bounded `--limit` |
| `report` | `--run-id` |
| `decide-proposal` | `--run-id`, `--proposal-id`, `--actor`, `--expected-version`, `--idempotency-key`, `--request` |
| `list-decisions` | `--run-id`; optional bounded `--limit` and `--offset` |
| `get-decision` | `--run-id`, `--decision-id` |
| `recover-decision` | `--run-id`, `--decision-id`, `--expected-version` |
| `run` | create fields plus optional `--execution-id`; create, execute, report |

The request file is 1..1,048,576 bytes of strict UTF-8 JSON, rejects duplicate
object keys and non-finite constants, and is parsed as the exact closed HTTP
caller-intent object shown above. In particular, the query appears only in
that file; it has no command-line form. Output is one bounded JSON document
with schema `router_dump_analyzer.private_analysis_cli_result.v1`, operation,
scope, success, exit code, and the operation-specific runner/run/report value.
For `decide-proposal`, the request file is the exact shared proposal-review
request above, not the run-creation request. It remains file-only so a human
target and rationale do not enter shell history. Decision commands use the same
wire projection as HTTP. Lossless integer and display-safe report rules are the same as HTTP. Exit `0`
means success; exit `2` is reserved for a completed `run` whose terminal
outcome contains an advisory error rather than a result; exit `1` means a
bounded command or service failure and emits the closed error document on
stderr. No CLI command retries, falls back to another runner or transport, or
automatically promotes proposals. Promotion requires the explicit
human-authored `decide-proposal` command; pending work requires the explicit
conditional `recover-decision` command.
`recover-expired` is a workspace-scoped maintenance mutation, not a model
retry: it returns a `runs` array containing only attempts terminalized in the
selected tenant/project/workspace. Rows protected by an unowned cleanup fence
remain pending because durable state contains no authority to reconstruct or
kill the original process.

Neither startup flag nor CLI document admits a public provider, model endpoint,
API key, network transport, arbitrary command, shell, ambient environment, or
fallback. The deployment owns the adapter to its approved local model and the
corresponding host/container egress controls.

Retention preview and execute accept a closed object with optional `catalog`
and `review` policy objects. Cutoffs use canonical decimal strings. The router
derives catalog external-reference protection itself and rejects a caller
attempt to assert it. Execute requires `Idempotency-Key`; exact replay returns
the completed prior result or resumes its first incomplete phase. The saga
freezes its effective clock; reuse with another actor, policy, or explicit
clock conflicts before mutation. Retention-result `evaluated_at_ns` fields are
canonical decimal strings. Every result also declares `observation_mode`.
Preview returns `best_effort_preview`: each store read is safe and bounded,
but the catalog, review, and ingestion inventories are independent snapshots
and a concurrent maintenance saga may advance between them. It is advisory and
must not be treated as an executable deletion plan. Execute returns
`coordinated_execution` and retains the ordered, durable saga guarantees below.
The nested ingestion report additionally declares
`host_storage_orphan_inventory`: preview returns `not_observed`, while execute
returns `bounded_host_scan`. A zero preview orphan count therefore does not
claim that host storage was scanned. Legacy completed execution journals
replay as `bounded_host_scan`.
Ingestion retention and admission quotas come from the server's versioned
retention-policy file, not from an HTTP request. Audit retrieval accepts a
bounded `limit` and returns the independent catalog, review, and ingestion
journals for that workspace. Preview does not wait for either the cross-store
mutation fence or the destructive ingestion-operation lock, is
workspace-scoped, and never scans host storage. Execute additionally advances independent durable
spool/blob/dataset/fixture host-reaper cursors monotonically in global
relative-path lexical order to EOF, then resets each completed
cycle. The host scan contributes `truncated: true` while at least one root has
more of its current cycle to inspect; workspace history may independently make
the aggregate report truncated. Exact unreferenced content-addressed objects
become eligible only after the configured orphan grace. An exact top-level core
fixture directory uses the same grace and requires absence of its fixture ID
from every tenant's ingestion rows; its children are not separate scan entries.
Discovery runs outside the upload fence; candidate identity plus applicable
global row-and-pin state are checked again under that fence and the identity is
journalled for crash-safe apply.

Retention execution commits an immutable plan and then checkpoints one
per-item outcome row in batches of at most 32. Operational logs may summarize
each committed batch and identify every database selection or host-root scan
that truncated at its bound, but those best-effort events are not a resume
cursor or audit API; the journal and response remain authoritative.

Catalog artifact-pin release is monotonic across process restart. Legacy
databases receive one transactional, versioned ownership backfill; ordinary
construction never recreates a pin from a completed import after the catalog
has released it. A later execute call can therefore resume the catalog saga
and converge the import row and unreferenced artifacts.

For an already pin-aware legacy database, the existing pin table is
authoritative. That older format has no release tombstone, so a missing pin
cannot be distinguished from an interrupted historical backfill. Upgrade
preserves the absence and never synthesizes ownership from completed import
rows.

Project and workspace creation accept a required `label`, optional caller
chosen ID, and optional bounded `metadata` object:

```json
{"project_id":"lab","label":"Lab","metadata":{"owner":"qa"}}
```

```json
{"workspace_id":"run-42","label":"Regression 42","metadata":{}}
```

A session creation has the same label/optional-ID/metadata shape. A session
member `PUT` body is:

```json
{
  "fixture_id": "fixture-...",
  "revision_id": "revision-...",
  "role": "before",
  "make_default": true
}
```

The member ID is the final path component. The exact fixture/revision must
belong to the workspace. A session can contain multiple revisions of the same
node because member identity is independent of node identity.

`PATCH .../sessions/{session_id}` requires at least one of `label` or
`metadata`; a supplied metadata object replaces the previous object. It
increments the session version and returns the new `ETag`. `DELETE` requires
the same optimistic preconditions, returns the removed descriptor with
`Cache-Control: no-store`, and conflicts when immutable snapshots still
reference the session. Snapshots are content-addressed immutable copies of the
member vector, default member, and source session version.

An import upload is **not multipart**. Its request body is the artifact bytes;
`original_name` is a required query parameter, `auto_select` defaults to
`true`, `preferred_plugin_id` is optional, and `Content-Type` is retained.
`X-Node-Hint` optionally supplies a node hint and `X-Import-Metadata`
optionally supplies a bounded JSON object. Only those caller-supplied parsing
inputs are visible to plug-in inventory/probe and parsing; tenant, project,
workspace, fixture, import, and principal coordinates remain core-private.
It returns `202` with an `ImportDescriptor`. Import states are the closed
values:

All other JSON-bearing control-plane mutation requests are bounded to 1 MiB
before model parsing. Oversized bodies return `413`; excessively nested JSON
or import-metadata headers return `422`. The streamed artifact upload keeps
its independent 8 GiB limit and is not buffered through the JSON boundary.

```text
admitting, queued, probing, awaiting_selection, ready, ingesting,
publishing, completed, failed, cancelled
```

`admitting` means the upload bytes and exact fixture-catalog request are
durably staged but the idempotent catalog receipt is not yet confirmed.
`publishing` means parsing and canonical dataset storage are complete and the
durable revision-publication outbox is replaying one exact idempotent catalog
operation. Resuming either stage replays its exact operation ID. Resuming a
publication failure does not invoke the plug-in again.

Catalog admission and publication use a deadline distinct from plug-in
execution. A deadline expiration has the closed public code
`catalog_execution_timeout`; it is an ambiguous outcome, so the exact
operation remains resumable and its content-addressed artifact stays pinned
until catalog reconciliation. Queue health reports unresolved catalog
timeouts as `catalog_attention_imports` immediately.

The descriptor exposes `attempt_count`, configured `max_attempts`, and
`attempts_remaining`. When `error` is non-null, that object repeats
`attempts_remaining` and derives `retryable` from the configured budget rather
than a hard-coded attempt count.

Every `ImportDescriptor` also exposes
`plugin_composition_policy_digest` as `sha256:<64 lowercase hex characters>`.
It identifies the exact core-owned composition policy admitted with the
upload. The value remains stable through get, list, selection, resume, and
terminal responses. A worker whose configured policy no longer has that
digest fails the claimed stage before catalog admission, probe, parsing, or
publication; it never silently publishes a differently composed execution
plan. The sole compatibility transition is an unfinished pre-contract import:
the upgrade transaction first removes its obsolete candidates and selection,
then binds the explicitly active policy before re-probe. Published history is
not eligible for that transition.

Selection repeats the exact candidate identity from the current candidate
response:

```json
{
  "probe_set_hash": "sha256:<64 lowercase hex characters>",
  "plugin_id": "example.router",
  "plugin_version": "1.2.3",
  "package_hash": "package-sha256:<64 lowercase hex characters>",
  "instance_id": "edge-parser.blue",
  "registered_execution_identity": "sha256:<64 lowercase hex characters>"
}
```

Every candidate response includes `instance_id` and
`registered_execution_identity`. New clients SHOULD echo both. The two fields
are an all-or-none pair: supplying only one is invalid. Omitting both retains
the compatibility path only when plug-in ID, version, and package identity
still identify exactly one candidate; two configured instances of the same
release therefore require the exact pair and otherwise return `409`.

`package_hash` is the field's compatibility name. It is an opaque exact
registry identity. A trusted loader can provide an immutable package/artifact
digest; otherwise the durable CLI and server control plane derive a bounded
`package-sha256:` digest from the complete regular- or namespace-package import
scope. Every search location for the first PEP 420 namespace ancestor
participates in import-precedence order even if a later component is a regular
package. A genuine top-level module receives a
distinct `module-sha256:` digest. Registry-derived identities are revalidated
immediately before execution. Sourceless `.pyc`/`.pyo` modules require a
trusted loader-supplied artifact digest because embedded build paths are not
relocation-stable. Programmatic
registries share that fail-closed default. A compatibility-only local/test
embedding must explicitly enable `allow_manifest_identity=True`; strict durable
commands and control planes reject that manifest-only registry. A trusted
deployment may admit it only with descriptor-owned
`allow_inline_only=True`.

When that opt-in registry can derive and revalidate package bytes but cannot
attest a stateful subprocess target, the registration is retained only for
explicitly trusted inline capability use. Its opaque
`registered_execution_identity` binds the `inline_only` restriction; the
candidate wire schema gains no compatibility field. Process workers and every
strict durable boundary reject the registration. An opted-in trusted-inline
boundary accepts it and stamps the weaker whole-plan authority. Strict
registries and explicit loader-supplied package identities do not downgrade to
this mode.
Durable pipeline construction takes sealed exact snapshots of its primary and
provider registries. Subsequent `register()`/`add_registered()` calls on the
caller-owned containers remain local and cannot change candidate selection or
published execution authority. Plan-bound capability routing also rejects an
`inline_only` record unless its router receives that same explicit deployment
policy and its v3-or-v4 plan records a trusted-inline authority.

By default, the durable servers and headless command execute both probe and
ingestion in fresh `spawn` child processes. The default child deadline is 300 seconds; the
headless command further caps it to the requested per-import `--timeout`.
Timeout includes spawn, plug-in execution, bounded result transfer, and clean
exit. A timed-out child is terminated, then killed if it does not exit, and is
reaped. Its import becomes `failed` with
`error.code="plugin_execution_timeout"`. Child startup/crash/protocol or
plug-in execution failures use `error.code="plugin_execution_failed"`.
Partial staged output is removed and neither case publishes a revision.

Programmatic embeddings may explicitly request synchronous `inline` execution
for trusted local/tests. That mode has no timeout or bounded cancellation
claim; only the default process mode is killable. It also has no subprocess
crash/CPU/memory containment; `close()` may stall or fail; and one live object
and its state may be shared across jobs, tenants, and concurrent workers with
ambient host access. All tenants/operators sharing the instance must trust it.
Use a thread-safe implementation or `max_workers=1`. Admission and publication
catalog calls have an independent deadline and execution-mode override; null
values inherit their plug-in equivalents. Production process mode includes
spawn, publisher work, result transfer, and exit in the enforced budget, then
terminates/kills/reaps an uncooperative child. The built-in SQLite publisher
reopens its durable catalog in the child and also bounds lock/busy waits through
commit. Core never pickles a custom publisher. It reconstructs one from an
explicit module-level `publisher_module_target`, or from an importable
no-argument publisher class; configured/stateful publishers must use the
explicit target. The reconstructed publisher should apply the supplied
remaining budget to real RPC connect/read/commit work. Trusted publisher
`inline` mode remains cooperative only. An ambiguous expiry retains the exact
idempotent outbox and artifact pin for reconciliation; isolated
startup/protocol/provider failures use `catalog_execution_failed`.

Probe/ingestion process components must be child-reconstructible. Core sends
only exact scalar/tuple bootstrap coordinates, never live plug-in, registry,
coordinator, decoder, provider, publisher, or bound-method objects. The child
loads module-level targets or no-argument classes, re-registers them, and
requires the same frozen execution identity. A target-only or frozen-limit
change therefore changes the plan authority and fails child attestation.
External plug-in/coordinator/decoder targets also carry exact static-import,
bounded module/package-byte, and Python-code identity; dynamic aliases and
sourceless targets are unavailable. Parent and child revalidate these
identities before execution, and the parent repeats the check on child-plan
readmission and final staging.
Configured/stateful components
must declare explicit process module targets. A non-default programmatic
`configuration_digest` requires a module-instance
`plugin_process_module_target` (not a constructor), and configured custom
coordinator/decoder state requires its corresponding explicit target. Process
pipeline construction validates those descriptors; installed and direct-module
loaders already supply their plug-in target. A loader MAY replace only the
plug-in's process coordinate when the exported live instance's exact concrete
class declares an immutable `PluginProcessBootstrapDescriptor` under the exact
class attribute `plugin_process_bootstrap`. The declaration is not inherited or
read through a descriptor. Its normalized target must resolve either to that
live instance or, with `construct_class=True`, to its exact no-argument concrete
class. The latter lets an application-facing live instance carry a parent-only
`runtime` adapter while the stateless parser is reconstructed without that
adapter in the child. It does not carry configuration and does not relax the
non-default-configuration rule. The artifact coordinate remains the selected
entry point/module instance; the distinct class constructor is recorded and
attested only as process-bootstrap identity.

This child boundary is killable
fault isolation, not a security sandbox: it does not remove the plug-in's
host-user filesystem, network, environment, or operating-system privileges.
Ingestion returns only bounded JSON metadata through IPC; the parent verifies
the child-written canonical dataset's file type, byte size, and SHA-256 under
its current fenced lease before content-addressed installation. It also
live-revalidates every selected auxiliary executable and manifest around
identity/schema reads and again at final child-plan acceptance; drift after
spawn rejects the metadata before revision staging.

Private-analysis process evidence factories apply the same executable-byte
principle to their `PACKAGE:ATTRIBUTE` bootstrap. Registration admits only an
exact source-backed module function or class and binds its defining module,
qualified attribute, callable kind, and bounded top-level-module or complete
package-scope fingerprint alongside configuration and deployment semantics.
Only that digest is retained; source paths and bytes are neither durable nor
wire values. The parent re-imports and rehashes immediately before `spawn`, and
the child independently repeats the check before invoking the factory.
Attribute replacement, file-byte drift, sourceless bytecode, dynamic aliases,
and other unverifiable targets therefore produce only a static preparation
failure under the already admitted authority.

The selection `Idempotency-Key` is a header, not a JSON field. Core persists a
scope-bound request digest and response. Repeating the exact key and request
returns the current import descriptor even after the import has advanced;
reusing that key for another request conflicts. A new key may be attached to
the already stored exact selection, but cannot change it.

Stored import events are ordered by `sequence`. Polling accepts
`after_sequence` and a `limit` up to 1,000. SSE uses the stored event type as
`event`, the sequence as `id`, emits keep-alives while idle, and emits `end`
after a terminal import has no more events.

Import lists are ordered by `(created_at_ns DESC, import_id DESC)`, default to
100 rows, and cap at 500. Their continuation is the tuple:

```json
{
  "before_created_at_ns": "1750000000000000000",
  "before_import_id": "import-..."
}
```

Clients copy both `next_cursor` fields into the next query. Supplying only one
field is invalid, and the tuple prevents tied creation timestamps from
skipping or repeating an import. Numeric cursor and event-sequence components
use canonical ASCII decimal syntax: no sign, whitespace, leading zeroes,
Unicode digits, or floating-point form.

A workspace admits at most 1,000 non-terminal imports by default. The check is
transactional and occurs after an exact upload-idempotency lookup, so retrying
an already admitted request remains valid at the cap. `completed`, `failed`,
and `cancelled` history does not consume it. A new request at the configured
cap conflicts.

Project, workspace, fixture, revision, session, and snapshot collections use
`limit`/`offset`, default to 1,000, cap at 5,000, and return `next_offset`.
Annotation and correlation collections accept the same bounded
`limit`/`offset` inputs. Soft deleted records are omitted unless
`include_deleted=true`. The review-audit feed uses `after_sequence`; its page
also defaults to 1,000 and caps at 5,000.
Numeric `offset`, `next_offset`, and sequence coordinates never exceed
`9007199254740991`; larger request values fail with `422`. Route-specific
limits such as the event log's 10,000,000 offset cap remain stricter.
`after_sequence`, `expected_audit_watermark`, retention
`audit_before_sequence`, `catalog_after_sequence`, and
`review_after_sequence` all use canonical unsigned ASCII decimal syntax and
this JSON-safe maximum.

Each annotation-list response also returns `audit_watermark` as a canonical
non-negative decimal string. The page rows and watermark come from one SQLite
read transaction. A client that continues an offset scan sends that first
value as `expected_audit_watermark` on every later page, including any
safety-cap probe. An `offset > 0` request without that precondition returns
`428`. If any review-overlay mutation changes the scope watermark, the endpoint
returns `409` instead of allowing a mixed-revision collection.
Leading-zero, signed, whitespace-padded, non-ASCII, floating-point, negative,
or greater-than-`9007199254740991` expected values return `422`. The store also
rejects audit-sequence exhaustion, and public reads fail closed if durable
state contains an out-of-domain sequence.

Annotation `kind` is `marker`, `note`, or `tag`. Each annotation has one to
5,000 exact subjects, optional title/body, and up to 64 unique tags:

```json
{
  "annotation_id": "review-1",
  "kind": "note",
  "subjects": [
    {
      "revision_id": "revision-...",
      "node_id": "node-a",
      "kind": "event",
      "subject_id": "event-..."
    }
  ],
  "title": "Check convergence",
  "body": "Observed later than the peer withdrawal.",
  "tags": ["incident-42"]
}
```

Subject `kind` is `event`, `source_record`, `resource`, `relationship`, or
`time_range`. Object subjects use `subject_id`; a time range uses ordered
`start_ns` and `end_ns` bounds in the current write API and omits `subject_id`.
Control-plane write requests accept canonical decimal strings for those two
values (and exact integers for non-browser compatibility). Responses
serialize declared core timestamp and interval fields as decimal strings.
Opaque plug-in or caller-owned mappings are not interpreted by suffix, so a
metadata key such as `hold_down_ns` retains its original JSON value and type.
Subject existence is checked against the exact immutable revision before a
write commits.

Core validates subject shape, uniqueness, and cardinality before loading any
revision. The shared `annotation_store.normalize_review_subjects(subjects, *,
maximum, event_only=False)` validates selection shape only; it does not grant
scope access or replace the coordinator's exact subject resolution.
`ControlPlaneLimits.max_subject_revisions` (default 128) and
`max_subject_dataset_bytes` (default 8 GiB) bound each admission. Every selected
revision must pass scope, dataset-path, individual-file, and aggregate-size
checks before the first dataset is decoded. Subjects are resolved by revision
without retaining a second collection of decoded datasets; their original
order is preserved. Reports reuse this preflight with their report-specific
limits. Explicit revision iterables stop at the limit plus one sentinel.

Catalog source-identity resolution applies `source_revision_id` within the
scoped SQL query, before pagination or the two-result ambiguity check. Matches
outside the first page therefore cannot be missed or falsely declared unique.

A manual correlation has two to 1,024 event subjects and one to 4,096 edges.
An edge names distinct subject-array ordinals, a plug-in/user-owned
`link_type`, and optional `directed` (default `true`). The object also accepts
`rationale`, tags, and optional finite `confidence` from zero through one.
On PATCH, omitting `confidence` preserves its value, explicit `null` clears it,
and a number replaces it. Invalid supplied values return `422` without changing
the object or its version; the existing `If-Match` requirement still applies.

Report selection is exactly one of explicit revisions, one current session,
or one immutable snapshot:

```json
{"revision_ids":["revision-a","revision-b"]}
```

```json
{"session_id":"review"}
```

```json
{"snapshot_id":"revision-set-..."}
```

The selectors are mutually exclusive and one non-empty selector is required;
there is no all-workspace fallback. Query `format=json` (default) returns canonical
`router_dump_analyzer.correlation_report.v2`; `format=markdown` returns the
derived human/AI-readable text. Both return
`ETag: "sha256:<report-digest>"` and a download filename. A session is read at
report time; a snapshot always uses its frozen vector. Empty selectors,
sessions, or snapshots are rejected rather than widened. Each report reads
review rows and their audit watermark from one transactional snapshot.
Default report bounds are 128 selected revisions, 8 GiB of aggregate
serialized revision datasets, 20,000 selected manual-correlation edges, and
10,000 projected event/source observations.
The report-owned `provenance_class` field uses the closed
`CorrelationReportProvenanceClass` values `plugin_inferred`, `user_asserted`,
and `core_corroboration`. It is separate from the plug-in fact `Provenance`
enum; plug-ins do not assign report provenance classes.
Every declared core-owned v2 report timestamp and interval bound is a
canonical decimal string. The `_ns` suffix does not reserve a key inside an
opaque plug-in mapping; such keys retain their original JSON values and types.
Every AI-facing string and object key passes one recursive core sanitizer.
The rule is principally Unicode-property based: control, unassigned,
surrogate, line-separator, and paragraph-separator categories (`Cc`, `Cn`,
`Cs`, `Zl`, and `Zp`), every format (`Cf`) character except U+200C ZWNJ and
U+200D ZWJ, every `Zs` separator except ordinary ASCII space, and the assigned
invisible or blank characters U+115F, U+1160, U+17B4, U+17B5, U+2800, U+3164,
U+FFA0, U+13441, and U+13442 are rendered as visible `\\uNNNN` or supplementary
`\\UNNNNNNNN` text. Ordinary tab and line breaks
remain valid report prose. This covers the complete Unicode TAG block, future
unassigned invisible code points, opaque plug-in metadata, and review labels.
U+16FE4 KHITAN SMALL SCRIPT FILLER remains valid as a legitimate cluster-layout
control inside visibly anchored text.
Combining grapheme joiner, unregistered or misplaced variation selectors,
U+FFFC OBJECT REPLACEMENT CHARACTER, and private-use (`Co`) text may remain in
bounded source display labels. The report renders those characters as visible
escapes while retaining surrounding text. U+FE0E/U+FE0F remain raw only when
the exact adjacent base-selector pair is present in the vendored Unicode 15
emoji-variation table. Multiple valid pairs across ZWJ sequences remain
intact; standalone, repeated-on-one-base, and unregistered selectors escape.
The stronger identifier boundary rejects every selector. Caller-supplied backslashes are
doubled before unsafe characters become escapes, so a literal `\uNNNN` or
`\UNNNNNNNN` string remains canonically and cryptographically distinct from
the corresponding Unicode character; object keys retain the same distinction.
Human review identifiers, titles, tags,
authors, and link types reject C0/DEL controls and bidi formatting controls;
annotation bodies and correlation rationales may retain ordinary tab and line
breaks but reject other C0/DEL controls.
Temporal corroboration across missing or different clock domains remains
`unknown` with `shared_resource_clock_unaligned`; it is never inferred from
raw numeric ordering alone.

Import descriptors, events, SSE, and CLI output expose one closed public
failure code/message. Arbitrary plug-in exception text is private diagnostic
state and has no HTTP route.

The control-plane and single-runtime routes use FastAPI `{"detail": ...}`
errors. Framework request-shape failures return one fixed bounded `422` detail
instead of echoing FastAPI's caller input. Adapter-owned safe `4xx` details
remain specific. Only
exact, explicitly declared public-domain validation/conflict exceptions may
publish their bounded, control-free message. Bare `ValueError` and `TypeError`
are internal faults: they return a closed `500` detail and never expose their
message, including filesystem or storage paths. Runtime temporal-topology,
multi-node topology/route, and source-record request errors have their own
declared exact classes; an undeclared subclass may inherit a status through
MRO but never permission to publish text. Runtime request nanoseconds use the
same signed 64-bit minimum and maximum as normalized core timestamps. The
shared decimal parser exposes closed grammar/below-minimum/above-maximum/
bit-limit reasons, so adapter-owned numeric fields and strong numeric ETags
retain precise range diagnostics without parsing exception prose. Public-text
projection selects a closed fallback for drive/UNC/POSIX paths, environment or
home expansion, Windows root-relative paths, and `../` or `..\` traversal;
boundary-aware detection preserves ordinary route/resource keys.
routes map an unverifiable
identity to `401`, resolved/header or role mismatch to
`403`, absent/out-of-scope data to `404`, conflicts to `409`, oversize uploads
to `413`, invalid bounded input to `422`, missing preconditions to `428`,
unconfigured control plane or identity resolver to `503`, and timeouts to
`504`. The complete operational, recovery, security, and core/plug-in
ownership rules are in [`control-plane.md`](control-plane.md).
Resolver-supplied response headers on authorization `401`/`403` results cross
an atomic bounded safe-header validator before they reach ASGI. One invalid
name, value, duplicate, forbidden framing/representation header, or oversized
map rejects the whole map and returns a bounded `500` without any
resolver-supplied headers. The original typed access denial is still reported
with its original phase/reason and actual `response_status=500`; the separate
zero-field
`control_plane.identity_resolver.response_headers_rejected` operational event
records the resolver-boundary fault without header, identity, or exception
data. `Set-Cookie` and obsolete `Set-Cookie2` are forbidden in every casing.
Session establishment and cookie mutation belong in authenticated upstream
middleware or dedicated endpoints; any future exception requires a typed,
explicit cookie policy instead of a general header allowlist. A response-side
`Cookie` field has no cookie-mutation semantics and remains subject to the
ordinary bounded checks.
Valid authentication/challenge and custom headers remain available to the
deployment resolver. Wire-valid `obs-text` bytes `0xA0`-`0xFF` remain
accepted; the core does not add behavior solely for Starlette's in-process
`TestClient`. If harness parity becomes necessary, the reopening rule is one
uniform printable-ASCII policy rather than a test-harness special case.

`Location`, `Refresh`, CORS response headers, CSP, and HSTS currently remain
under that generic bounded policy; this is compatibility, not an endorsement
that an identity resolver owns redirect/origin/security policy. The recommended
future boundary is a typed deployment allowlist: deny those policy primitives
and response `Authorization` by default, retain `WWW-Authenticate`, and admit
only registered custom headers. It is intentionally not enabled until resolver
compatibility has been surveyed.

## 2. Time basis

Every state, graph, finding, and route response contains exactly one basis.

Observed capture vector:

```json
{
  "kind": "observed_capture_vector",
  "capture_ranges": [
    {
      "scope": "control-plane/ROUTE/blue/203.0.113.0/24",
      "observed_at_min_ns": "1759680005000000000",
      "observed_at_max_ns": "1759680005000000000",
      "clock_domain": "node-a-realtime",
      "evidence_ids": ["ev-status-route-1"]
    },
    {
      "scope": "control-plane/NBR/blue/192.0.2.0",
      "observed_at_min_ns": "1759680004998000000",
      "observed_at_max_ns": "1759680005002000000",
      "clock_domain": "node-a-realtime",
      "evidence_ids": ["ev-status-nbr-1"]
    }
  ],
  "provenance": "observed",
  "quality": "exact"
}
```

Reconstructed time:

```json
{
  "kind": "reconstructed_time",
  "requested_time_ns": "1759680003015000000",
  "resolved_at_min_ns": "1759680003014000000",
  "resolved_at_max_ns": "1759680003016000000",
  "clock_domain": "normalized:revision",
  "provenance": "reconstructed",
  "quality": "best_effort"
}
```

The server rejects an observed request if the caller demands one simultaneous
instant but the relevant capture ranges do not overlap.

External topology and state consumers may instead provide an explicit temporal
selector. An absolute selector is:

```json
{
  "kind": "absolute_time",
  "time_ns": "1759680005000000000",
  "clock_domain": "utc",
  "clock_policy": "strict"
}
```

The server maps that instant into every selected node independently. The
resolved `WorldBasis` echoes the selector and includes one result per node:

```json
{
  "kind": "absolute_time",
  "requested_time_ns": "1759680005000000000",
  "resolved_at_min_ns": "1759680004998000000",
  "resolved_at_max_ns": "1759680005002000000",
  "clock_domain": "utc",
  "selector": {
    "kind": "absolute_time",
    "time_ns": "1759680005000000000",
    "clock_domain": "utc",
    "clock_policy": "strict"
  },
  "node_resolutions": [
    {
      "node_id": "node-a",
      "local_clock_domain": "node-a-monotonic",
      "local_min_ns": "812345009000",
      "local_max_ns": "812345013000",
      "absolute_min_ns": "1759680004998000000",
      "absolute_max_ns": "1759680005002000000",
      "mapping_method": "piecewise_clock_anchors",
      "quality": "best_effort",
      "reason_code": null,
      "evidence_ids": ["clock-anchor-a-19"]
    },
    {
      "node_id": "node-b",
      "local_clock_domain": null,
      "local_min_ns": null,
      "local_max_ns": null,
      "absolute_min_ns": null,
      "absolute_max_ns": null,
      "mapping_method": null,
      "quality": "unknown",
      "reason_code": "clock_unaligned",
      "evidence_ids": []
    }
  ],
  "provenance": "reconstructed",
  "quality": "unknown"
}
```

A relative selector is anchored to the latest complete status watermark for one
exact scope:

```json
{
  "kind": "relative_to_watermark",
  "offset_ns": "-5000000000",
  "scope": {
    "node_id": "node-a",
    "status_perspective_id": "hardware-observed",
    "topology_projection_id": "underlay-connectivity"
  },
  "clock_policy": "strict"
}
```

`offset_ns` is zero or negative. The anchor is not the greatest event timestamp;
it is the latest complete `ReconstructionWatermark` for exactly the requested
node, status perspective, and optional topology projection. Cross-node relative
queries return `kind: "relative_capture_vector"` because each node has its own
anchor. They do not claim a simultaneous absolute instant.

A relative result may contain exact local bounds and `null` absolute bounds.
That node is still locally reconstructable; lack of a wall-clock transform only
prevents treating it as part of a simultaneous absolute snapshot. Absolute
selectors accept only clock domains advertised by provider discovery; an
unknown domain returns `422`.

The runtime declaration is scoped as
`watermarks[status_perspective_id][topology_projection_id]` and supplies
`local_time_ns`, `clock_domain`, and `complete`; `query_time_ns`, mapping
metadata/quality, and the paired `absolute_min_ns`/`absolute_max_ns` bounds are
optional. Supplying only one absolute bound is invalid, and `complete: false`
cannot anchor a query. The coordinator qualifies the declaration with the
node/member, revision, plug-in set, plug-in run, projection, and perspective in
`watermark_scope`. An explicit local-only anchor returns
`watermark_source: "projection_declaration"`, `resolution: "local_exact"`,
`query_time_ns: null`, and null absolute bounds without requiring a clock
mapping.

If an older topology provider has no exact scoped declaration, the executable
compatibility path may derive the anchor from assembly capture time minus that
projection's declared watermark lag. This path still requires a node clock
mapping and returns `watermark_source: "legacy_capture_lag"`. New providers
must declare explicit scoped watermarks.

Under `strict` policy, raw timestamps from different clock domains are never
compared directly. A missing transform returns a per-node `clock_unaligned`
result and unknown state. If the mapped uncertainty interval crosses a state or
relationship transition, all supported alternatives are returned with
`quality: "ambiguous"`; the server does not choose one endpoint. `best_effort`
may use a recorded assumption, but it must expose the mapping method, evidence,
and degraded quality. No policy silently substitutes another timestamp, node,
status perspective, or topology projection.

The built-in temporal query service reads the snapshot interval valid at the
requested local time, including empty states and explicit absence. It samples
state and lifecycle transitions inside the mapped uncertainty window, not only
events or window endpoints. Later snapshots are not replaced by timeline-start
state, and events already represented by an interval are not replayed twice.
Independent named perspectives require a perspective-aware reader: embedders
can connect `TemporalTopologyService.perspective_state_reader` to
`NormalizedDataService.resource_state_at(..., perspective_ref=...)`. The legacy
two-argument reader remains valid for an unqualified single perspective; it
cannot establish exact status for a different named perspective.

## 3. State query

Request:

```http
POST /v1/revisions/rev-01/state/query
Content-Type: application/json
```

```json
{
  "basis": {"kind": "absolute_time", "time_ns": "1759680003015000000", "clock_domain": "utc"},
  "status_perspective_id": "hardware-observed",
  "resource_ids": ["res-route-1", "res-ete-b"],
  "include_relationships": true,
  "relation_types": ["depends_on", "references"],
  "page_size": 500,
  "resource_cursor": null
}
```

The shipped adapter returns `basis` (also aliased as `resolved_basis`) with
`requested`, `kind`, `clock_policy`, `anchor`, `simultaneity`, and per-node
resolutions. Absolute requests resolve to `kind: "absolute_time"`; relative
requests resolve to `"relative_capture_vector"`. `reconstructed_time` is a
typed world-basis concept, not an accepted selector for this HTTP adapter.

The response also contains `node_times`, selected projection/perspective IDs,
`resources`, `relationships`, `counts`, `completeness`, and independent paging
handles. Resource rows have canonical `resource_id`, tri-state `exists`,
`state`/`properties`, status, validity bounds, quality, unknown fields, and
possible states for an ambiguous clock window. Relationship rows use `source`
and `target` resource IDs, not `source_resource_id`/`target_resource_id`.
Additional identity/evidence fields depend on the admitted provider data; this
adapter does not promise the typed plug-in `ResourceKey.parts` wire envelope.

`include_relationships` defaults to true and accepts a JSON boolean. False
returns no relationships and does not query the relationship reader.
`relation_types`, when supplied, is an array of strings that narrows the
selected plug-in projection's relationship types; it cannot broaden that
projection. An empty array selects no relationship types; omit the field to
use the projection's defaults.

For another resource page, copy `next_resource_cursor` into `resource_cursor`
and keep the revision, basis, perspective, resource IDs, and kinds unchanged.
Use `next_change_cursor` as `change_cursor` for change pages. The generic
`next_cursor` response is a legacy convenience, not a request-field name:
non-null `cursor` requests are rejected so they cannot silently repeat page one.
Cursor positions and offsets are bounded JSON-safe integers. An out-of-range
position, or a page whose position/count arithmetic would exceed that range,
returns `422`; recomputing a cursor checksum does not bypass those checks.

`status_perspective_id` selects one declared independent layer-local view. The
server returns `422` for an undeclared perspective. When that perspective lacks
status for an otherwise known resource, the row remains present with unknown
status; the server neither borrows another perspective nor removes the resource.

## 4. Topology providers, snapshots, and changes

Provider discovery is revision-scoped:

```http
GET /v1/revisions/rev-01/topology/providers
```

```json
{
  "revision_id": "rev-01",
  "status_perspectives": [
    {
      "perspective_id": "control-intended",
      "label": "Control-plane intent",
      "layer_id": "control-plane",
      "role": "intended"
    },
    {
      "perspective_id": "hardware-observed",
      "label": "Observed hardware",
      "layer_id": "hardware-driver-plane",
      "role": "observed"
    }
  ],
  "topology_projections": [
    {
      "projection_id": "underlay-connectivity",
      "label": "Underlay connectivity",
      "supported_status_perspective_ids": [
        "control-intended",
        "hardware-observed"
      ],
      "default_status_perspective_id": "hardware-observed",
      "status_source_combination_policy": "all_required_usable"
    }
  ]
}
```

Topology and status are selected independently:

```http
POST /v1/revisions/rev-01/topology/query
Content-Type: application/json
```

```json
{
  "basis": {
    "kind": "absolute_time",
    "time_ns": "1759680005000000000",
    "clock_domain": "utc",
    "clock_policy": "strict"
  },
  "node_ids": ["node-a", "node-b"],
  "topology_projection_id": "underlay-connectivity",
  "status_perspective_id": "hardware-observed",
  "include_resources": true,
  "include_relationships": true,
  "page_size": 500,
  "resource_cursor": null
}
```

The response contains the resolved `basis`, selected descriptor IDs, generic
`resources` and `relationships` from the state contract, plus plugin-inferred
projection records. Each record has a discriminated resource, endpoint, or link
payload and `usability` (`usable`, `unusable`, `degraded`, or `unknown`), source
resource IDs, properties/unknowns, validity, provenance, quality, and evidence.
Endpoint references contain exactly one canonical resource or declarative match.
Matching targets carry a namespaced plugin matcher ID, typed arguments, and the
plugin-resolved candidate set; the core does not interpret proprietary matching
semantics.

Opaque match arguments and candidate keys in this response are already
type-tagged normalized transport values. Consumers validate and canonicalize
that form directly rather than applying raw-value normalization again.
Transport wrappers do not count as logical nesting. Unknown tags, invalid or
extra fields/encodings, non-canonical or duplicate mapping entries, and a
candidate `typed_key` inconsistent with its normalized key are rejected as
invalid evidence.

```json
{
  "revision_id": "rev-01",
  "topology_projection_id": "underlay-connectivity",
  "status_perspective_id": "hardware-observed",
  "basis": {"kind": "absolute_time", "node_resolutions": []},
  "resources": [],
  "relationships": [],
  "projection_records": [
    {
      "projection_id": "underlay-connectivity",
      "status_perspective_id": "hardware-observed",
      "payload": {
        "kind": "link",
        "link_id": "topo-link-17",
        "source": {
          "kind": "exact_resource",
          "resource_id": "res-node-a-eth2"
        },
        "target": {
          "kind": "match",
          "matcher_id": "synthetic.peer-by-system-id",
          "arguments": {"system_id": "0000.0000.0002"},
          "resolved_candidate_resource_ids": ["res-node-b-eth7"]
        },
        "directed": false
      },
      "usability": "unknown",
      "exists": true,
      "source_resource_ids": ["res-node-a-eth2"],
      "properties": {},
      "unknown_fields": [
        {
          "name": "usability",
          "reason_code": "selected_perspective_status_missing",
          "evidence_ids": []
        }
      ],
      "valid_from_ns": "1759680003000000000",
      "valid_to_ns": null,
      "provenance": "correlated",
      "quality": "unknown",
      "evidence_ids": ["ev-peer-match-17"]
    }
  ],
  "complete": false,
  "next_cursor": null,
  "truncated": false
}
```

Topology identity and operational status are distinct. Switching from
`control-intended` to `hardware-observed` may change usability without changing
node, port, or link identities. Missing selected-perspective status produces
unknown usability. The server never treats a generic `depends_on` edge as a link
unless the selected plugin projection emitted it as connectivity, and it never
uses a descriptor's display default after the caller explicitly selected a
perspective.

Topology existence is also tri-state and independent from usability. A clock
window that crosses relationship creation/removal returns a possible record
with `exists: null`, supported presence alternatives, and unknown or ambiguous
usability; clients must not count it as a definite link.

For normalized topology resources represented by `initial_status`,
`initial_state`, and time-ordered `changes[]`, the snapshot applies only changes
at or before the resolved basis. An applied change may update `status`, merge
`state`, and set boolean `exists`. If `exists` is absent, generic `operation`
values `create`/`add`/`insert` imply `true` and `delete`/`remove` imply
`false`; explicit `exists` takes precedence. `state_changed: false` makes the
complete change a no-op. A plain status transition such as `up` to `down` does
not change existence.

Resource validity is an independent outer gate:
`valid_from_ns <= basis_time_ns < valid_to_ns`, with either bound optional.
Lifecycle changes cannot extend that half-open range. Within the range, delete
and recreate changes form an absence gap while preserving the canonical
resource identity; the response reports `status: "absent"` during that gap.

Historical replay is also available:

```http
POST /v1/revisions/rev-01/topology/changes/query
```

The request supplies `start_basis`, `end_basis`, the same projection and status
perspective IDs, a page size, and an opaque `change_cursor` copied from the
previous response's `next_cursor`. The response streams ordered
resource existence/status changes and inferred-connectivity add/remove/status
changes. Every change carries its node-local effective range, normalized
absolute range when supported, uncertainty, before/after value, cause/evidence,
provenance, and quality. Pagination is revision/query-bound. This is a bounded
change stream over retained events and relationship intervals, not a complete
snapshot-reconciliation log: snapshot-only resource transitions need a fresh
`topology/query`, and an event exactly at the end basis belongs to the next
window. Do not reconstruct the complete end snapshot from these pages alone.
The query window is half-open:
`start_ns <= effective_time_ns < end_ns` for both resource events and
relationship mutations. A change on the shared boundary of adjacent windows is
returned exactly once by the later window, and a zero-width window is empty.
Changes at the same effective timestamp are ordered by
`source_sequence` and then their stable event/change identifier. A modify after
a delete does not recreate a resource. For a multi-node basis with non-zero
clock uncertainty, the coordinator evaluates every state boundary inside the
mapped interval; a transition-crossing interval returns the possible states
with `quality: "ambiguous"` rather than silently choosing the center sample.

An unsupported projection/perspective combination returns `422`. A selected
node whose clock cannot be aligned under strict policy remains in the response
with `clock_unaligned`, unknown state, and `complete: false`; it is not silently
dropped. If a caller explicitly requires a complete simultaneous result, the
request fails unless every selected node has overlapping supported absolute
ranges.

### 4.1 Heterogeneous multi-node assemblies

Multi-node reconstruction is assembly-scoped because its members may reference
different immutable revisions and unrelated plug-in sets:

```http
GET /v1/topology-assemblies/fabric-01/capabilities
POST /v1/topology-assemblies/fabric-01/query
```

Capabilities list every member's installed/active plug-in sets and the valid
projection/perspective matrix for each plug-in run. Callers construct a separate
selection for every member; local descriptor IDs are never assumed to match:

```json
{
  "basis": {
    "kind": "absolute_time",
    "time_ns": "1759680005000000000",
    "clock_domain": "utc"
  },
  "clock_policy": "strict",
  "member_selections": [
    {
      "member_id": "pe-a",
      "plugin_set_id": "alpha-evpn-1",
      "projection_ref": {
        "plugin_run_id": "run-alpha-7",
        "projection_id": "alpha.fabric-links"
      },
      "perspective_ref": {
        "plugin_run_id": "run-alpha-7",
        "perspective_id": "alpha.hardware"
      }
    },
    {
      "member_id": "pe-b",
      "plugin_set_id": "beta-router-2",
      "projection_ref": {
        "plugin_run_id": "run-beta-4",
        "projection_id": "beta.underlay"
      },
      "perspective_ref": {
        "plugin_run_id": "run-beta-4",
        "perspective_id": "beta.asic-observed"
      }
    }
  ],
  "linker_ref": {
    "plugin_run_id": "run-federation-2",
    "linker_id": "demo.cross-vendor-boundary"
  },
  "resource_limit": 100,
  "inter_node_link_limit": 500
}
```

The capabilities response always includes the concrete `assembly_id`. A
`topology_profiles[]` entry may also contain:

```json
{
  "profile_id": "tenant-vpn",
  "label": "Tenant VPN",
  "presentation_roles": ["vpn", "overlay"],
  "empty_action_label": "Show tenant VPN"
}
```

The same response advertises the complete coordinate contract for historical
reconstruction:

```json
{
  "defaults": {
    "basis": {
      "kind": "relative_to_watermark",
      "offset_ns": "0"
    },
    "clock_policy": "best_effort"
  },
  "time_bounds": {
    "start_ns": "1759680000000000000",
    "end_ns": "1759680600000000000",
    "capture_ns": "1759680600000000000"
  },
  "absolute_clock_domains": ["utc"],
  "time_bases": [
    {"kind": "absolute_time", "required": ["time_ns"]},
    {"kind": "relative_to_watermark", "required": ["offset_ns"]}
  ]
}
```

All three bounds are decimal-string nanoseconds. They describe the history
window advertised for this immutable assembly; they are not plug-in-provided
pixel coordinates. The generic core browser maps an absolute selector across
`[start_ns,end_ns]`. For a watermark-relative selector it maps the same history
window to `[start_ns - capture_ns,0]` and submits the selected value as
`offset_ns`. The subtraction and inverse range mapping use integer arithmetic,
so JavaScript clients must not coerce these values through `Number`.

After a successful query, `resolved_basis.requested` is the selector applied to
the displayed graph. The form and range handle may contain a newer draft
selector, but moving that handle does not relabel the existing graph: click,
drag, or keyboard commit submits another reconstruction, and only its successful
response becomes the new applied basis. Clients should show applied and draft
positions separately and disable the range while a request is pending or while
the two axes are incomparable.

For `relative_to_watermark`, one displayed offset is resolved independently
against every selected projection watermark. A resulting
`relative_capture_vector` or `mixed_capture_vector` is never labeled as UTC or
one simultaneous moment. This selector and its coordinate transform are
core-browser behavior. A node or federation plug-in supplies the declared
history/watermark evidence and semantic projection; it does not supply the
range control, executable frontend code, or a replacement time interpretation.

`presentation_roles` is a bounded array of opaque, declared role tokens. The
generic browser uses the exact `vpn` token to offer a VPN-oriented view; it
does not infer VPN meaning from profile, plug-in, projection, protocol, VRF, or
resource names. `empty_action_label` is optional safe display text for the
empty-state action. The coordinator validates and transports these fields. In
the executable v1 boundary they belong to the coordinator/assembly topology
profile envelope around a selected plug-in projection; the typed
`TopologyProjectionDescriptor` does not expose them directly. Provider policy
owns their meaning, and adding a direct device-plug-in field requires a
versioned protocol addition.

The demo accepts `node_queries` as an equivalent executable spelling of
`member_selections`; production clients should use the capability-advertised
field names and API version. Every returned resource uses the structured global
reference `(member_id, revision_id, resource_id)`. Inter-node links retain both
endpoint references, plug-in-run provenance, tri-state existence/usability,
and `resolution` (`matched`, `ambiguous`, `unresolved`, or `conflict`) with all
bounded candidates. The core never selects the first ambiguous candidate.
When paired claims disagree on normalized `link_type`, the coordinator emits a
deterministic conflict with `link_type: "unknown"`, sorted distinct
`claimed_link_types`, unknown operational status, and reason
`plugin_link_type_mismatch`; claim order cannot select a winner. A conflicting
presentation role is likewise fail-closed and cannot become a physical route
hop.

The response also contains `context_id`, per-member clock/watermark resolution,
coverage reasons, independent counts/cursors, and core-generated navigation
targets. A node page resolves the frozen context through:

```http
GET /v1/topology-contexts/{context_id}/members/{member_id}
```

The returned target restores the exact node-local basis and semantic selection;
relative links therefore do not drift when a watermark advances. Browser
navigation starts at the primary multi-node topology page `/` (with `/topology`
retained as a compatibility alias), opens an individual member workspace at
`/node`, and returns to `/` while preserving the context and focused global
resource or link.
Context identifiers are server-owned, tenant/authorization-bound, versioned,
and expiring in production. Plug-ins may not provide URLs.

Each local plug-in emits normalized endpoint claims. The core may equality-join
only an explicitly declared exact-token claim contract. Any semantic matching,
alias handling, reciprocity policy, or cross-vendor inference is performed by
the selected federation/linker plug-in and returned with provenance/evidence.
Missing clocks, revisions, plug-ins, watermarks, or candidates remain scoped
partial results with reason codes.

The typed `ConnectorClaim` supplies `link_type` (default `connector`) and
`presentation: InterNodeLinkPresentation` (default `route_trace: include`).
For an otherwise exact two-claim match, disagreement in either normalized
field produces `conflict`; link-type conflicts use `link_type: unknown`, sorted
`claimed_link_types`, and `plugin_link_type_mismatch`, while route-trace-role
conflicts use the core-only `conflict` role and
`plugin_route_trace_role_mismatch`. `unresolved` results have no candidates,
`matched` has exactly one, `ambiguous` at least two, and `conflict` at least
one.

Federation linker registration and execution are trusted, synchronous inline
calls. The API intentionally has no in-process federation timeout setting or
timeout result; deployments needing a killable deadline must supervise the
linker in a separate process.

The executable v1 response makes typed-claim coverage explicit alongside the
legacy segment view:

```json
{
  "counts": {
    "typed_connector_claims": 6,
    "unresolved_typed_connector_claims": 0
  },
  "completeness": {
    "typed_federation_complete": true,
    "typed_federation_truncated": false,
    "inactive_typed_connector_claims": 0,
    "unresolved_typed_connector_claims": []
  }
}
```

Every typed `connector_resolutions[]` item identifies the policy and claim
contract, reports per-state counts, execution provenance
(`core_exact_token` or `linker_plugin`), linker identity when applicable, and
independent `complete`/`truncated` flags. This array is the bounded audit of all
matched, unresolved, ambiguous, and conflicting outcomes. Only complete,
non-truncated matched outcomes with complete qualified endpoints are promoted
to authoritative typed `inter_node_links[]`; incomplete or non-matched audit
results MUST NOT be rendered as graph edges. Those graph links carry global
endpoints, operational quality, match-policy identity, and an
`inference.owner` of `core_exact_matcher` or `federation_linker_plugin`. An
unresolved claim is a complete resolution when
the selected query intentionally contains no compatible remote member; it is
listed under `unresolved_typed_connector_claims` but does not by itself make
the execution partial. Truncation or provider failure does.

Typed record and claim validity uses half-open intervals over the selected
world's resolved uncertainty bounds. The projection selection
`basis_time_ns` must equal `WorldBasis.requested_time_ns`. A bounded claim is
authoritative only when `valid_from_ns <= resolved_at_min_ns` and
`resolved_at_max_ns < valid_to_ns`, with either validity bound optional. A
wholly disjoint claim is inactive; a validity boundary crossing the resolved
interval, or a bounded claim with no resolved member basis, is omitted and
reported through unknown-basis counts and incomplete coverage. Inactive
claims, including duplicates, consume the claim input budget before filtering.
The typed node result returns
`topology_endpoints[]` as well as resources and local links. Its resource page
reports exact `returned_count` and `truncated`; `total_count` is `null` when the
provider record stream is incomplete and otherwise is the exact eligible
total.

Frozen catalog, member, revision, plug-in, projection, and perspective
coordinates retain exact string types; the API does not stringify values or
substitute another revision. Endpoint status is scoped by those coordinates,
so multiple projections or perspectives cannot overwrite one another. Claim,
result, and candidate properties, evidence, provenance, and quality remain in
the bounded audit payload, including every grouped result that made a match
ambiguous. Same-member fanout is therefore visible and input-order invariant.
For strict route-boundary completion, a typed link is usable evidence only when
`resolution` is `matched`, `federation_complete` is true, and
`federation_truncated` is false, and `presentation.route_trace` is `include`.
An `overlay` link remains presentation-only. A directed link additionally
requires the route boundary's ordered source and target to match the exact
member, revision, plug-in instance, projection, perspective, and typed resource
identity exposed by `endpoint_a`/`source` and `endpoint_b`/`target`; the reverse
order remains unresolved. An undirected link accepts either exact order.
Malformed, inconsistent, or partially qualified typed endpoints fail closed.
All other typed states remain unresolved or best-effort incomplete.

A matched typed identity does not turn unknown operational status into an
observed route. With `operational_status: "unknown"`, `strict` mode emits an
inactive unresolved boundary with `observed: false` and reason
`typed_boundary_operational_status_unknown`. `best_effort` mode may retain the
selected branch as provisional `best_effort_inferred` reachability, but keeps
`observed: false`, reduces confidence, and attaches that reason plus explicit
core-inference provenance. `usable` and `unusable` remain complete observed
states; an unusable boundary is inactive.

A generated next-hop declaration selects this path with one
`typed_inter_node_link` entry (other reference kinds may coexist):

```json
{
  "topology_references": [
    {
      "reference_kind": "typed_inter_node_link",
      "source_endpoint": {
        "node_id": "node-a",
        "resource_id": "interface/a",
        "typed_resource_key": {
          "namespace": "example",
          "node": "node-a",
          "layer": "underlay",
          "kind": "INTERFACE",
          "parts": [
            {"name": "name", "value": {"type": "string", "value": "a"}}
          ]
        }
      },
      "target_endpoint": {
        "node_id": "node-b",
        "resource_id": "interface/b",
        "typed_resource_key": {
          "namespace": "example",
          "node": "node-b",
          "layer": "underlay",
          "kind": "INTERFACE",
          "parts": [
            {"name": "name", "value": {"type": "string", "value": "b"}}
          ]
        }
      }
    }
  ]
}
```

The reference is exact and ordered, but deliberately uses only coordinates the
forwarding plug-in can declare: endpoint node, its current local next-hop
resource ID, and its typed `ResourceKey`. It contains no core-generated link
ID and no member/revision/provider qualification. Core binds the two keys to
the frozen topology endpoints and selects exactly one candidate only through
the resulting fully qualified endpoint equality. If the typed reference is
present but malformed, missing, multiply matched, reversed for a directed
link, overlay-only, incomplete, or truncated, the boundary remains unresolved
even when a legacy connectivity-domain reference also appears in the
declaration. When no typed reference is present, the existing exact
domain/attachment join and legacy unordered local-resource link matching
remain compatible. A typed boundary additionally requires the response-level
`completeness.typed_federation_complete` to be exactly `true` and
both `completeness.typed_federation_truncated` and
`completeness.inter_node_links_truncated` to be exactly `false`; an
individually complete link cannot make globally partial evidence or a partial
link page authoritative. A missing link-page truncation flag also fails
closed. Overall/node resource-preview pagination remains independent: a
partial record preview does not invalidate a complete typed claim/link page.
A resolved boundary copies the link's validated `inference.owner`
(`core_exact_matcher` or `federation_linker_plugin`) into
`graph_presentation.semantic_owner`. Core-exact boundaries use
`text_source: "core_exact_join_summary"`; linker-owned boundaries use
`text_source: "federation_linker_resolution_summary"` and describe the
allowlisted linker result while limiting core's role to exact endpoint
validation. `semantic_ownership.boundary_resolution` is computed from complete
rendered boundaries and is one of `core_exact_matcher`,
`federation_linker_plugin`, `node_topology_plugin`, `mixed`, or `none`.

#### Shared-medium segment projection

A local plug-in represents a subnet or other multi-access medium with the
existing v1 graph payloads: one `TopologyResourceRecord` whose plug-in-owned
role is `connectivity-domain`, optional `TopologyEndpointRecord` port anchors,
and one ordinary `TopologyLinkRecord` from each interface attachment to the
domain resource. This is a bipartite projection, not an N-squared set of node
links and not a new core hyperedge type. Segment role and identity details—such
as prefix, VRF, VLAN, VPN, management, loopback, external, LAG, subinterface,
physical-member, route, and neighbor interpretation—remain plug-in properties.

For assembly consumers, the coordinator exposes a normalized view:

- `network_segments[]` contains a stable assembly-scoped `segment_id`, the
  versioned matcher contract and typed opaque key, plug-in semantics and any
  merge-critical conflicts, current and observed member counts, operational
  status, quality/confidence/evidence, time alignment, and bounded `members`.
- `segment_attachments[]` contains a stable attachment ID, global endpoint and
  component resource references, the plug-in's opaque attachment model,
  current existence/status, validity interval, resolved observation time,
  inference rule, provenance, evidence, and node deep link.
- `segment_resolutions[]` records `shared`, `single_sided`, `absent`, semantic
  conflict, or unsupported matcher-contract outcomes. The core equality-groups
  only matchers advertised with `match_semantics: exact_token` and
  `result_shape: connectivity_domain`; it never merges by prefix alone.

The `segment_id` digest is scoped by assembly ID, matcher ID, matcher-contract
version, and a recursively type-tagged opaque key, so integer `1` and string
`"1"`, a UUID and its display string, or binary bytes and a similar-looking
string cannot collide. The normalized key returned by the API is JSON-safe;
binary atoms use base64 and arbitrarily large integers use decimal strings.
Attachment IDs use stable member/revision/resource/domain identity (plus an
optional explicit plug-in attachment key), never the ephemeral plug-in run ID.
A single current attachment means only *single-sided in this query
scope*. It is external only when the plug-in explicitly classifies it as such
and declares complete applicable coverage. Management and loopback exclusion,
and VPN placement in a separate presentation plane, are likewise plug-in
decisions.
In the browser, an explicit presentation plane is authoritative over the
legacy `is_vpn` fallback. An omitted optional `separate_view` flag does not hide
a VPN domain; explicit `false` still excludes it from that display. Attachment
normalization honors both existing flat fields and declared
`attachment_model.kind`/`components`; logical kinds do not become physical
interfaces merely because a resource reference is present.

The typed provider boundary for this normalized envelope is
`TopologyPluginSemanticsDescriptor`. `role` stays open bounded plug-in
vocabulary, while `TopologyDomainRole.EXTERNAL` is the only generic
core-actionable role and requires the literal boolean
`coverage_complete: true`. The API preserves the wire value `"external"`.
The entire semantics envelope is bounded and strict-JSON-safe before it is
compared or returned; scalar types remain distinct in merge-critical
comparison. Invalid keys, non-finite numbers, Python-only objects, cycles, and
oversized values fail the request rather than being stringified.

Presentation does not change this model. A plug-in may set the bounded
`topology_presentation.two_participant_shape` property to `compact_edge` (the
typed API equivalent is `TopologyResourcePresentation` with
`TopologyTwoParticipantShape.COMPACT_EDGE`). The core honors that request only
when the selected physical-domain result is conflict-free, coverage is
complete, all expected current attachments are present, and those attachments
resolve to exactly two distinct current participants. It then draws one
node-boundary-to-node-boundary line while retaining the original `segment_id`,
attachment IDs, evidence, provenance, validity, and inspection targets. It does
not fabricate an `inter_node_link` or remove the domain from the API.

The default is `domain_node`. Multi-access, VPN, one-sided, incomplete,
conflicted, or unresolved domains remain explicit domain objects. The core
does not inspect prefix length, address overlap, VRF, VLAN, protocol, medium
name, or label to decide whether a domain is pairwise. Plug-ins own that
semantic declaration and its explanation/evidence; the core owns fail-closed
validation, generic line-versus-domain rendering, layout, and accessible hover
or pinned inspection.

`network_segment_limit` and `segment_attachment_limit` bound this view.
`completeness.network_segments_truncated`,
`completeness.segment_attachments_truncated`, and
`completeness.unresolved_network_segment_claims` prevent partial membership
from looking complete. Attachment validity is evaluated at the resolved basis
together with endpoint-resource existence; inactive historical attachments
remain in the bounded result with `exists: false` but are not current members.
`claim_valid_at_basis` and `endpoint_exists_at_basis` distinguish claim-window
absence from endpoint-resource absence. Validity is half-open: `valid_from_ns`
is inclusive and `valid_to_ns` is exclusive. The resource preview/page limit
does not prune claims or attachments; those use their independent bounded
topology limits.

`inter_node_links` remains a route-trace compatibility projection. Such links
carry `projection_role: route_trace_compatibility` and are suppressed in the
physical topology whenever the segment projection is available. They are not
drawn in parallel with subnet spokes and are not silently treated as segment
membership.

Each input claim's `presentation.route_trace` is validated through
`InterNodeLinkPresentation`: accepted plug-in wire values are `"include"` and
`"overlay"`, with `"include"` as the default. `"conflict"` is not a valid
plug-in input. It is emitted only by core when the two peer claims disagree;
that result also uses `projection_role: presentation_conflict` and unknown
operational state so a presentation disagreement cannot become a physical
route hop.

## 5. Route resolution

### 5.1 Advertised single-node route choices

The generic node workspace never hard-codes a destination or infers a route
from plug-in attributes. It first reads the selected revision's bounded,
node-scoped capability:

```http
GET /v1/revisions/{revision_id}/routes/capabilities
```

```json
{
  "available": true,
  "plugin_defined": true,
  "scope": "node",
  "node_id": "node-a",
  "revision_id": "demo/node-a/revision-0001",
  "provider": {
    "plugin_id": "demo.example-router",
    "plugin_version": "0.1.0"
  },
  "routes": [
    {
      "route_id": "node-a/route/single-active-primary",
      "label": "Single-active primary path",
      "destination": "demo:node-b:single-active-primary",
      "scenario_id": "single-active-primary",
      "route_type": "mpls_transport",
      "route_family": "mpls_labeled_unicast",
      "address_family": "mpls",
      "vrf": "default",
      "decision": "active",
      "observed_at_ns": "1759680600000000000"
    }
  ],
  "basis_kinds": [
    {
      "basis_kind": "observed_capture_vector",
      "label": "Observed plug-in projection"
    }
  ],
  "default_route_id": "node-a/route/single-active-primary",
  "default_basis_kind": "observed_capture_vector"
}
```

`route_id` is an opaque plug-in/projection-owned identity within the immutable
revision. It may contain `/`; neither core nor the browser parses it. The
coordinator validates that every advertised route belongs to this node and
revision, de-duplicates exact IDs, and exposes only the basis kinds it can
execute. Labels, destination vocabulary, route family/type, labels/SIDs,
encapsulation, next-hop semantics, and explanation remain plug-in-owned.
Plug-ins do not supply endpoint URLs or executable browser controls.

The browser resolves one advertised choice by exact identity:

```http
POST /v1/revisions/{revision_id}/routes/resolve
```

```json
{
  "route_id": "node-a/route/single-active-primary",
  "basis_kind": "observed_capture_vector"
}
```

The server rejects an unadvertised `route_id` or basis with `422`; it does not
fall back to a global route, a hard-coded destination, or string matching. The
response echoes `route_id`, `revision_id`, the resolved basis, plug-in
provenance, matched destination, branches, route attributes, and the
explanation tree. A point-in-time topology-member snapshot may expose no route
capability; the core frontend then renders the feature unavailable rather than
calling a resolver for another revision.

This normalized capability is currently a coordinator adapter over
plug-in-projected route rows. It is not a new `AnalyzerPlugin` hook in the v1
Python protocol. A production coordinator may derive the same shape from
`FORWARDING_PROJECTION` or another versioned plug-in projection without
changing the browser contract.

### 5.2 Arbitrary-destination forwarding query profile

The protocol-neutral forwarding IR also supports a coordinator-owned
arbitrary-destination query. This is a separate, capability-advertised request
profile; a client must not send it to a resolver that advertises only the
`route_id` choices above. A production request profile may use:

```json
{
  "basis": {"kind": "reconstructed_time", "time_ns": "1759680005000000000"},
  "vrf_resource_id": "res-vrf-blue",
  "destination": "203.0.113.42",
  "traffic_class": "known_unicast",
  "ingress_policy_scopes": [
    {
      "contract_id": "vendor.example.evpn-split-horizon.v1",
      "arguments": [["ethernet_segment", "esi-01"], ["evi", 320]]
    }
  ],
  "ingress_policy_scopes_complete": true,
  "max_hops": 64,
  "max_recursion": 32,
  "max_branches": 256
}
```

Response fields are stable even when resolution is incomplete:

```json
{
  "revision_id": "rev-01",
  "basis": {
    "kind": "reconstructed_time",
    "requested_time_ns": "1759680005000000000",
    "resolved_at_min_ns": "1759680005000000000",
    "resolved_at_max_ns": "1759680005000000000",
    "clock_domain": "normalized:revision",
    "provenance": "reconstructed",
    "quality": "best_effort"
  },
  "result": "resolved",
  "matched_prefix": "203.0.113.0/24",
  "branches": [
    {
      "next_hop": "192.0.2.0",
      "egress_interface_resource_id": "res-if-eth1",
      "quality": "best_effort",
      "unresolved": []
    }
  ],
  "explanation": {
    "kind": "fib_entry",
    "resource_id": "res-route-1",
    "evidence_ids": ["ev-status-route-1"],
    "children": [
      {"kind": "adjacency", "resource_id": "res-nbr-ok", "evidence_ids": ["ev-status-nbr-1"], "children": []}
    ]
  },
  "provenance": "reconstructed",
  "quality": "best_effort"
}
```

`traffic_class` and `ingress_policy_scopes` are optional typed context.
`ingress_policy_scopes_complete` distinguishes a known-empty or known non-match
from incomplete evidence and defaults to `true` for compatibility. Scope
contract IDs, argument order and values are plug-in-owned; core compares a
complete scope only by exact equality. If a constraint names traffic classes
and the request omits the class, or an applicable scope does not match while
the set is incomplete, the decision is unknown rather than guessed. An exact
match is still sufficient to block.

`result` is `resolved`, `partially_resolved`, `unresolved`, `policy_blocked`,
`cycle`, `hop_limit_exceeded`, or `recursion_limit_exceeded`. A cycle, policy
block, or exhausted budget is a normal bounded result, not an HTTP 500. A
`cycle` result includes the first and closing traversal-step indexes and the
closed canonical state sequence. A `policy_blocked` branch includes the
affected candidate plus `policy_decisions[]`, with the plug-in constraint,
ingress scopes, `ingress_scopes_complete`, traffic class, verdict, explanation,
and evidence. Rejected candidates remain inspectable.

### 5.3 Trace-time packet IR

The public Python plug-in boundary additionally defines one node-local packet
step. This is not a promise that every HTTP route calls the hook. The advanced
multi-node demo scenarios consume demo-provider transition declarations and
the core evaluation helpers, while a future production coordinator may
repeatedly invoke the already-defined `FORWARDING_TRACE` hook across installed
members without changing its ownership:

- `ForwardingStepRequest` supplies one stable step ID, member, qualified
  perspective, forwarding object, current packet state, lookup/ingress context,
  bounded steering rules, `max_candidates`, and the negotiated forwarding IR
  version.
- `ForwardingStepResult` echoes the step ID and supplies one
  `ForwardingPacketTransition`, selected candidate, next local forwarding
  object/context, recursive/terminal flags, and quality. `continue` is
  non-terminal and requires a next object; every other disposition is terminal
  for the current linear branch and has no next object/context.
- `ForwardingPacketState.layers[]` is ordered outermost to innermost. Each
  layer has a stable opaque ID, plug-in-owned contract ID and typed fields,
  optional declared bytes, and completeness. Core treats the contract and
  fields as exact opaque data. Its human label is presentation-only and is not
  part of equality, hashing, continuity, or structural change detection.
- A transition has exact `before` and `after` states, action contract and
  display label, normalized disposition, origin, actor, optional MTU
  constraint, optional forced-rule provenance, and bounded resolution
  contributions.

The normalized transition dispositions are `continue`, `deliver`, `drop`,
`punt`, `replicate`, and `unknown`. A terminal or replicate disposition stops
the current linear chain; a final `continue` yields
`continuation_required`. These values do not tell core whether an opaque
layer is MPLS, SRv6, VXLAN, IP-in-IP, a VPN, or proprietary state. The node
plug-in declares that meaning and the resulting disposition. Core validates
ordering and exact continuity, reports structural layer changes, stops on a
terminal disposition, rejects any supplied transition suffix after that
terminal result, and enforces a separate packet-step budget. Structural
`moved` layers are relative reorders among retained layers; adding or removing
an outer wrapper does not move all retained inner layers. The structural diff
also declares whether both packet identities were complete.

Coordinators validate hook output with
`validate_forwarding_step_result(request, result)`. This checks the exact step
and packet-before state and couples a selected user steering rule to its
forced-rule provenance and declared candidate/packet/disposition overrides.
The capability executor retains a detached authority snapshot and passes a
separate request copy to the plug-in. Packet state, resource keys, lookup
context, and steering rules are deeply detached; changing the hook copy cannot
rewrite the step/member or fabricate user steering that was absent from the
authorized request. Projection output is likewise checked against a retained
IR/perspective/budget snapshot rather than the plug-in-visible request object.

Packet size and MTU fields are comparable only when their complete
`basis_contract_id` values match exactly. The generic MTU result is
`not_declared`, `unknown`, `unknown_basis_mismatch`, `fits`, or `exceeds`.
Transition evaluation compares the `after` packet size with the transition's
MTU constraint. `exceeds` reports integer excess bytes but does not itself
imply drop, fragmentation, punt, or ICMP generation; those remain
plug-in-declared device semantics.

A user `ForwardingSteeringRule` targets one exact step and may require one
exact packet-before state. It may select a candidate, replace the packet-after
state, or override disposition. The resulting transition is
`origin=user_forced`, contains actor/rule provenance, and is counterfactual.
Observed device policy is `origin=node_plugin`. A counterfactual trace must not
be returned as observed reachability or mutate the stored forwarding
projection.

Equal packet values do not prove continuity if either identity is incomplete.
Core retains that uncertainty through terminal transitions, independently of
the declared delivery disposition. A generic plug-in DROP is not an MTU
failure: that label requires a matching core MTU result of `exceeds`.
User-forced transitions and their resulting path remain counterfactual, not
observed device decisions.

The bundled advanced demo accepts an advertised `steering_profile_id` and
returns its evaluated teaching payload under `paths[].packet_trace`. That
object contains `initial_state`, `transitions[]`, `outcome`, `continuity`,
terminal disposition, and an explicit `counterfactual` flag. Every transition
keeps its stable `step_id` and `segment_id`, exact before/after states, core
diff, core MTU result, plug-in action/disposition/actor, and forced-rule
provenance. Packet layers are serialized in their declared order:

```json
{
  "packet_trace": {
    "layer_order": "outermost_to_innermost",
    "outcome": "deliver",
    "continuity": "complete",
    "counterfactual": false,
    "transitions": [
      {
        "transition": {
          "step_id": "segment:route-path:source",
          "action_contract_id": "vendor.example.packet-action.v1",
          "action_label": "Plug-in-owned action",
          "disposition": "continue",
          "origin": "node_plugin",
          "before": {"layers": [], "complete": true},
          "after": {"layers": [], "complete": true}
        },
        "diff": {
          "added_layer_ids": [],
          "removed_layer_ids": [],
          "changed_layer_ids": [],
          "moved_layer_ids": []
        },
        "mtu": {"outcome": "not_declared"}
      }
    ]
  }
}
```

This JSON shape is a demo adapter over the public Python contracts. A browser
renders only declared labels, fields, diffs, and outcomes; it does not infer
protocol semantics from strings or contract IDs.

At an inter-member boundary, the federation linker returns matched,
ambiguous, unresolved, or conflicting connector candidates. It may preserve an
exact compatible packet contract or perform an explicit linker-owned mapping;
it must not silently push, pop, reorder, or reinterpret packet layers.

### 5.4 Cross-node multi-path trace

The executable demo discovers and traces routes through independently
reconstructed members and their heterogeneous plug-ins:

```http
GET  /v1/topology-assemblies/demo.fabric.multi-node/routes/capabilities
POST /v1/topology-assemblies/demo.fabric.multi-node/routes/trace
```

The capabilities response advertises immutable traffic sources and
destinations, independent trace start points, route-resolver plug-ins,
route-type/family/VRF facets, strict/best-effort modes, and bounded review
scenarios. It also advertises packet-trace bounds, layer order, ownership, and
the steering profiles accepted by each scenario. `limits.max_candidate_paths`
and `limits.max_segments_per_path` are enforced before path materialization;
core-derived hop and recursion positions are checked against any plug-in
declarations. The heterogeneous demo covers
connected and recursive-static routes, IPv4/IPv6 unicast, IS-IS, MPLS transport
and L3VPN, SRv6, and EVPN type 2/type 5 resolution. A demo request reuses the
frozen topology context and may focus any returned path, including an inactive
or retained dead one:

```json
{
  "topology_context_id": "tctx1-2ebdfcbed0d01148d88e67d1",
  "scenario_id": "transit-start-endpoint-reachability",
  "direction": "both",
  "flow": {
    "source": {"endpoint_id": "endpoint:node-a:loopback"},
    "destination": {"endpoint_id": "endpoint:node-b:loopback"}
  },
  "ingress": {"start_id": "start:transit-p-1"},
  "resolution_mode": "best_effort",
  "basis": {"kind": "relative_to_watermark", "offset_ns": "0"}
}
```

`flow.source` and `flow.destination` identify one immutable traffic flow.
Top-level `source`/`source_id` and `destination`/`destination_id` remain
compatibility aliases, but they do not independently select the traversal seed.
When no explicit forward start is supplied, core derives it from a declared
source endpoint attachment. `ingress` selects the forward observation/start
point and may therefore be a transit member or resource unrelated to the source
endpoint's attachment. `trace_starts.forward` is the per-direction form of the
same selection. An explicit
`trace_starts.reverse` or `reverse_ingress` may select a known return
observation point; otherwise the return trace starts from a plug-in-declared
attachment of the traffic destination. It targets the exact traffic source
endpoint and is never required to revisit the forward ingress.
For a bidirectional endpoint-to-endpoint verdict, an explicit reverse start
must itself resolve to an available attachment of `flow.destination`.
An arbitrary mid-return observation can still be traced as a single direction,
but it cannot prove reachability from the destination endpoint.

A compatibility executor fixed to one declared endpoint pair may accept that
same pair in either order. For the reversed pair, the coordinator uses the
executor's opposite directional candidates and per-visit decisions while
preserving the caller-facing `direction`; a counterpart request reverses the
caller's flow, not the executor's original labels. A fixed scenario with a
multi-attachment destination is rejected on reversal unless it declares an
explicit source-attachment contract.

The response returns a flat, ordered `paths[]` candidate set plus
`multipath`, `focused_path_id`, `route_resolution_sequence[]`, `issues[]`,
`interaction_targets[]`, `completeness`, and `context_consistency` envelopes.
Every segment carries stable resource/link targets, plug-in provenance,
activity/primary state, confidence, issue references, and a plug-in-provided
`route_resolution` object. All-active scenarios have multiple active members
and no fabricated singular primary; single-active scenarios may retain inactive
eligible standby or withdrawn/dead candidates for inspection. Cross-layer
scenarios preserve control-plane and observed-FIB disagreement as typed findings
instead of rewriting one layer to agree with the other.
New projections always declare their path-group mode. The route-executor v1
compatibility envelope may omit `multipath_mode` only when at most one candidate
is selected; the coordinator normalizes that case to `single_active`. Multiple
selected candidates without an explicit mode fail validation rather than being
interpreted as ECMP.

Each directional response also returns the immutable `flow`, its
`trace_start`, the direction's `goal_endpoint`, and `endpoint_reachability`.
Each path's `terminal_reachability` identifies the requested and observed
terminal endpoint, terminal member/attachment, exact-match result, completeness,
and semantic ownership. The node plug-in classifies local delivery and supplies
the normalized attachment evidence; the core validates exact identities and
aggregates active branches. A directional result is `reached`, `not_reached`,
`unknown`, or `partial_active_reachability`. The last state means at least one
plug-in-selected active branch reaches the endpoint and at least one does not;
core does not promote that multipath set to fully reachable. A continuous,
complete path that ends at the forward ingress instead of the requested
endpoint is `not_reached`.

Each endpoint attachment carries a time-valid `state` of `available`,
`unavailable`, or `withdrawn` plus `can_terminate`. Withdrawn and unavailable
attachments remain inspectable evidence but cannot terminate a successful
trace. Every route candidate declares its VRF/routing scope explicitly; the
core does not supply an implicit `"default"` value or parse destination CIDR
text to invent endpoint aliases. A proven exact-state cycle is a terminal
`cycle` result with `end_to_end_resolved: false`, never a resolved path.

A bidirectional response classifies endpoint reachability as
`bidirectionally_reachable`, `one_way_reachable`, `both_unreachable`, or
`unknown_incomplete`. It is consistent only when the forward direction reaches
`flow.destination` and the return direction reaches `flow.source`.
`path_relation.state` is separately `symmetric`, `asymmetric`, or
`not_comparable`. It describes node-sequence shape and never changes the
endpoint-reachability verdict. In particular, a forward trace that begins
inside the flow at a transit member cannot be meaningfully reversed and uses
`not_comparable` with reason `forward_starts_inside_flow_path`.
If the return start has not been verified as a destination attachment, path
shape is `not_comparable` with reason `reverse_endpoint_start_unknown`; a
separately established bidirectional endpoint result remains intact.

Every path may additionally carry ordered `node_occurrences[]`. Each occurrence
has a stable `occurrence_id` separate from physical node identity, and segments
may use `source_occurrence_id` and `target_occurrence_id`. This preserves a
closing repeated visit such as A -> P1 -> B -> P1; clients must not deduplicate
it into the earlier P1 card. A cycle path has `result: "cycle"`,
`terminal_reason`, and a `cycle` envelope that identifies the first and closing
occurrences. The server checks complete canonical forwarding state, not router
identity alone, before declaring the cycle.
Compatibility candidate traversal declarations therefore carry
`identity_complete`, which defaults to false and may be true only when the
opaque key covers every cycle-relevant component. The response publishes this
as `canonical_identity_complete`. Equal incomplete keys do not mark an
occurrence repeated and cannot produce `result: "cycle"`; hop and recursion
budgets still bound such a trace.

An ingress-policy rejection has `result: "policy_blocked"` and retains
`policy_decisions[]`. A decision includes the stable decision/constraint
identity, accept/reject outcome, reason, typed plug-in scope references, scope
completeness, traffic applicability, explanation, evidence, and provider. This
is an intentional candidate exclusion, distinct from a failed or dead
adjacency. Federation does not assume that different plug-ins' contract IDs are
compatible; the linker must preserve or explicitly map a scope contract,
otherwise it marks the receiving scope set incomplete.
`max_hops` and `max_recursion` are independently advertised and validated;
their exhausted results remain distinct from a cycle even when the retained
diagnostic prefix could eventually loop.

Resolution segments and their text parts may additionally carry
`highlight_target_ids[]`. Each ID references one typed `interaction_targets[]`
entry with `kind: topology_node` or `kind: topology_link`. This is the exact
graph-level focus chosen by the node or federation plug-in: a node-local
resolution normally names one node, while a boundary resolution names one
link. Broad `interaction_target_ids[]` remain the full supporting evidence and
must not be substituted for the exact highlight set. The core validates and
preserves these opaque IDs; it does not infer a target by parsing explanation
text. Older plug-ins without this annotation receive only an identity-based
node/link fallback, never adjacency-wide token matching.

`route_resolution_evidence` keeps the visible `topology_context_id`
authoritative while identifying any auxiliary, same-capture-vector plug-in
projection snapshot used by the resolvers. This matters when the visible map
is intentionally filtered to one layer, such as underlay forwarding, but an
alternative path needs EVPN control-state evidence. Removing that display
filter for route evidence does not replace the selected topology context or
promote an inferred result to observed ground truth.

The production-generalized envelope below shows how the same contract expands
to arbitrary ingress/ground-truth selections and bounded comparison views:

```http
POST /v1/topology-assemblies/fabric-01/routes/trace
```

A request either supplies a previously frozen `context_id` or the full temporal
and per-member selections accepted by the assembly query. It also makes path and
completeness policy explicit:

```json
{
  "context_id": "tctx1-fabric-1759680005",
  "flow": {
    "source": {
      "endpoint_id": "endpoint:site-a:2001-db8-10-10",
      "kind": "ipv6",
      "value": "2001:db8:10::10"
    },
    "destination": {
      "endpoint_id": "endpoint:site-b:2001-db8-100-42",
      "kind": "ipv6",
      "value": "2001:db8:100::42"
    }
  },
  "ingress": {
    "member_id": "pe-a",
    "start_id": "start:pe-a",
    "vrf_resource_ref": {
      "member_id": "pe-a",
      "revision_id": "rev-a-17",
      "resource_id": "VRF/blue"
    },
    "traffic_class": "known_unicast",
    "policy_scopes": [],
    "policy_scopes_complete": false
  },
  "ground_truth": {
    "policy": "selected_perspective",
    "perspective_by_member": {
      "pe-a": "alpha.hardware",
      "pe-b": "beta.asic-observed"
    }
  },
  "path_selection": "include_standby",
  "completeness_policy": "strict",
  "limits": {
    "max_hops": 32,
    "max_branches": 256,
    "max_local_candidates_per_hop": 16,
    "max_boundary_candidates": 8
  }
}
```

The `flow` survives direction changes unchanged. For the forward direction,
`goal_endpoint` is `flow.destination`; for the return direction it is
`flow.source`. `ingress` is only the forward traversal seed. The core obtains
the default return seed from the destination's bounded, time-valid attachment
candidates supplied through node and federation projections. Missing,
ambiguous, or incomplete attachment evidence remains unknown under the selected
completeness policy instead of being replaced by the forward ingress.

Optional `comparison_views[]` entries each name a stable `view_id` and a
`perspective_by_member` map, for example control-plane perspectives to compare
with hardware-selected ground truth. They do not override `ground_truth`.

`path_selection` is `active_only`, `include_standby`, or `all_candidates`; it
does not change the plug-in-declared group mode. A `single_active` group yields
at most one selected `primary` plus optional non-forwarding `standby` paths. If
the primary cannot be determined, the paths are `alternative` candidates rather
than fabricated primary/standby roles. An `all_active` group yields one `ecmp`
branch for each explicitly declared active member. Equal rank by itself never
creates ECMP, and the server does not infer traffic shares from branch count.

The response uses stable ordering and separates the aggregate result from each
branch:

```json
{
  "trace_id": "trace1-6f1d",
  "context_id": "tctx1-fabric-1759680005",
  "result": "resolved",
  "complete": true,
  "completeness_policy": "strict",
  "flow": {
    "source": {"endpoint_id": "endpoint:site-a:2001-db8-10-10"},
    "destination": {"endpoint_id": "endpoint:site-b:2001-db8-100-42"}
  },
  "trace_start": {
    "start_id": "start:pe-a",
    "member_id": "pe-a",
    "semantic_role": "traversal_seed"
  },
  "goal_endpoint": {
    "endpoint_id": "endpoint:site-b:2001-db8-100-42"
  },
  "endpoint_reachability": {
    "state": "reached",
    "reaches_target": true,
    "criterion": "exact_normalized_endpoint_attachment"
  },
  "ground_truth": {
    "policy": "selected_perspective",
    "quality": "exact"
  },
  "path_groups": [
    {
      "group_id": "group:pe-a:blue:2001-db8-100",
      "mode": "single_active",
      "paths": [
        {
          "path_id": "path:primary:8c2a",
          "branch_id": "branch:primary:0",
          "role": "primary",
          "result": "resolved",
          "quality": "exact",
          "presentations": [
            {
              "presentation_id": "alpha.vpn-blue.service-overlay",
              "role": "overlay",
              "scope": "path",
              "style": "band",
              "label": "Tenant Blue service",
              "topology_references": [
                {
                  "match": {
                    "matcher_id": "alpha.connectivity-domain.exact.v1",
                    "arguments": {"domain_key": "vpn:blue"}
                  }
                }
              ],
              "anchor_resources": [],
              "facts": {"routing_scope": "blue"}
            }
          ],
          "steps": [
            {
              "step_index": 0,
              "step_id": "step:8c2a:0",
              "phase": "local_lookup",
              "member_id": "pe-a",
              "resolution_text": "VRF blue matched 2001:db8:100::/64",
              "resource_refs": [],
              "provenance": {"plugin_run_id": "run-alpha-7"},
              "quality": "exact",
              "unknowns": []
            },
            {
              "step_index": 1,
              "step_id": "step:8c2a:1",
              "phase": "federation_boundary",
              "member_id": "pe-a",
              "resolution_text": "Boundary matched to pe-b",
              "provenance": {"plugin_run_id": "run-federation-2"},
              "quality": "exact",
              "unknowns": []
            }
          ]
        }
      ]
    }
  ],
  "consistency_findings": [],
  "coverage": {"complete": true, "reasons": []},
  "navigation": {
    "topology_href": "/?context_id=tctx1-fabric-1759680005&path_id=path%3Aprimary%3A8c2a",
    "step_href_template": "/node?context_id=tctx1-fabric-1759680005&path_id={path_id}&step_id={step_id}"
  }
}
```

`steps[]` is always ordered by ascending `step_index`; a stable `step_id` is
bound to the immutable context, path branch, member, canonical resource
references, and normalized phase, not to `resolution_text`. Normalized phases
include `local_lookup`, `candidate_selection`, `next_hop`, `failover`,
`tunnel_action`, `adjacency_egress`, `federation_boundary`, and
`remote_ingress`. Node plug-ins own local `resolution_text`, local candidates,
proprietary status interpretation, typed policy scopes/constraints, the
canonical local lookup/packet context, endpoint attachment declarations, and
local terminal/delivery classification. The core owns temporal/context
resolution, immutable flow direction, exact endpoint and constraint
evaluation, budgets, branch expansion, exact canonical-state cycle detection,
stable ordering, coverage, comparison, and navigation. Core owns only
type-preserving equality for an explicitly declared exact-token boundary. An
allowlisted federation linker owns semantic inter-node boundary and
endpoint-attachment matching for an explicitly declared linker policy and
returns its candidate evidence; neither path reinterprets a node plug-in's
split-horizon or local delivery decision.

For a generated immutable projection, the version-2 evidence shape is more
specific than the normalized response above. Each coverage case declares
forward and reverse `candidate_paths`. Every involved node contributes
`directional_decisions` keyed by direction, with each occurrence identified by
the exact `(candidate_id, visit_index)` pair. The node plug-in owns the
candidate sequence, active/primary/alternative state, local
decision/disposition, and `resolution_text`. A crossing next hop contains one
typed `connectivity_domain` reference with the plug-in's matcher ID/version and
opaque key, plus local and remote attachment resource IDs.

Core resolves that declaration only by exact equality against the selected
normalized topology snapshot. A successful result returns the exact
`network_segment_id`, `source_attachment_id`, and `target_attachment_id`;
missing, multiple, truncated, conflicting, non-current, or unusable evidence is
reason-coded and unresolved. Prefix, address, VLAN, label/SID, node-pair, and
display-text inference are forbidden.
Exact segment keys use the core's recursively type-tagged comparison profile:
missing and null differ, mapping-key types are retained, and only finite floats
are accepted. Keys are bounded to four nested container levels, 32 items per
container, 1,024 total value units, 4,096-character/byte atoms, and 4,096-bit
integers. Invalid or over-bound snapshot keys are not candidates; an invalid
requested key is a request error.

The generated-demo coverage transport also has exact non-route evidence.
`topology_claim` records carry the claim and attachment IDs, opaque matcher and
segment key, prefix/classification, validity, and plug-in calculation metadata.
`temporal_event` records carry a real event UID, timestamp, phase, event and
resource kinds, action, outcome, and `state_changed`. These are demo fixture
validation records, not a requirement that every production coordinator expose
the generator's coverage registry through this route response.

`paths[].presentations[]` is the bounded, core-preserved form of the
`RoutePresentationDescriptor` sidecars encountered while resolving the path.
`presentation_id` is stable and opaque. `role` is `principal`, `overlay`, or
`annotation`; `scope` is `path`, `step`, `span`, or `resource`; and `style` is
one of the safe semantic primitives `path`, `band`, `badge`, or `callout`.
Topology references contain either a canonical resource identity or a declared
exact-match topology reference. The response may add resolved topology target
IDs, but it must retain an unresolved reference and reason when exact resolution
is unavailable. `anchor_resources` bind step or span presentations by
identity, never by parsing text.

Presentations do not add hops, replace the outer L1-L3 path, or affect path
selection and reachability. Labels and `facts` remain plug-in-owned display
data: the server and client must not infer VPN, MPLS, SRv6, EVPN, VLAN, or other
protocol semantics from them. Styles are mapped by the core UI theme; CSS,
HTML, coordinates, and executable renderer content are not accepted.

The core may add resolved `endpoint_refs` or `topology_targets` to these
descriptors. Plug-ins author the canonical `style`, `topology_references`,
`anchor_resources`, mapping-valued `facts`, and `description` fields shown
above. `presentations` is the sole response field; clients must not require or
produce a demo-only alias.

Every `comparison_views[]` entry produces a `comparison_results[]` item with the
same complete `path_groups[]` schema and its own coverage. Different
perspectives are traced independently. `consistency_findings[]` references path
and first-divergent-step IDs that exist in the ground-truth or comparison
results and describes next-hop, egress-interface, destination, encapsulation,
reachability, or update-lag differences. The server never splices preferred
steps from multiple layers into a synthetic path.

For materialized route scenarios, a finding with explicit
`affects_consistency: true` contributes to the inconsistent verdict and
`consistency.issue_refs` independently of its plug-in-owned category. Explicit
`false` remains informational. This does not change packet continuity checks
or turn a configuration disagreement into proof that a reachable path drops
traffic; direction and affected path references still scope the finding.

With `completeness_policy: "strict"`, an unavailable required member,
unsupported status perspective, unknown required status, unaligned clock, or
ambiguous/unresolved boundary makes the trace incomplete. Diagnostic path
prefixes may still be returned, but there is no inferred continuation. With
`best_effort`, bounded alternatives may continue and every affected step and
path carries assumption reason codes, observation times, provenance, quality,
and unknowns. Best-effort provenance is evidence for a provisional answer only;
it must not be promoted to ground truth or silently reused as exact topology or
reachability by another query.

The UI uses `path_id`, `branch_id`, and `step_id` as focus keys. Hover and
keyboard focus highlight the ordered fabric nodes/links and show a bounded card
with role, group mode, result, hop count, egress/encapsulation, first divergence,
and uncertainty. Click pins that focus; a step action opens its frozen member at
`/node`, and the return URL restores the same path. Hover never mutates the
selected time or reconstruction context.

### 5.5 Federated route-table rows

The assembly route-table query is:

```http
POST /v1/topology-assemblies/{assembly_id}/routes/tables/query
```

It returns bounded, plug-in-owned route rows under the frozen assembly context.
Rows that name an executable generated case carry an exact trace request.
Inventory-only rows, including a generated row whose `scenario_id` is null,
remain visible but return:

```json
{
  "traceable": false,
  "trace_query": {},
  "trace_unavailable_reason": "This local inventory route has no plug-in-declared cross-node candidate."
}
```

The browser disables trace action for that row. It must not derive a source,
destination, VRF, candidate path, or scenario from display fields. The plug-in
owns whether a route has a traceable candidate and all route/label/SID
semantics; core owns bounded federation, identity validation, and transport of
the explicit capability.

## 6. Timeline and cluster expansion

Timeline query:

```json
{
  "lane_ids": ["control-plane/ROUTE/blue/203.0.113.0/24", "data-bridge/ETE/etg-100/path-a"],
  "start_ns": "1759680000000000000",
  "end_ns": "1759680010000000000",
  "viewport_pixels": 1440,
  "max_glyphs": 3000,
  "filters": {"outcomes": ["failure", "unknown"]}
}
```

Each returned lane is permanently bound to one canonical resource. It contains
separate lifecycle and status intervals plus marks describing that event's
effect on this resource, rather than a single event being assigned to its first
subject:

```json
{
  "lane_id": "data-bridge/ETE/etg-100/path-a",
  "resource": {
    "resource_id": "data-bridge/ETE/etg-100/path-a",
    "kind": "ETE",
    "layer": "data-bridge",
    "label": "path-a"
  },
  "has_lifecycle_history": true,
  "lifecycle_intervals": [
    {
      "start_ns": "1759680001000000000",
      "end_ns": null,
      "opened_by_event_uid": "event-100",
      "closed_by_event_uid": null,
      "incarnation": 1
    }
  ],
  "status_intervals": [
    {
      "start_ns": "1759680001000000000",
      "end_ns": "1759680005000000000",
      "condition": "ok",
      "properties": {"program_state": "programmed"},
      "opened_by_event_uid": "event-100"
    }
  ],
  "event_marks": [
    {
      "event_uid": "event-100",
      "timestamp_ns": "1759680001000000000",
      "raw_action": "add",
      "effect": "created",
      "outcome": "success",
      "status_valid_to_ns": "1759680005000000000"
    }
  ]
}
```

An `UPSERT` against an absent/present resource is exposed as `created` or
`modified` respectively. A successful delete is `deleted`. An event with no
accepted mutation can still have an `unchanged` mark, which is how a typical
failed programming callback remains visible without splitting the status bar.
Unknown snapshot boundaries are open or hatched; they are not converted into
fabricated create/delete events.

`has_lifecycle_history` is core-owned and reports whether that resource has any
lifecycle evidence in the full revision, before filtering this query window.
Clients MUST preserve empty returned lifecycle/status arrays. Within the
response's half-open `[start_ns, end_ns)` window, a missing live interval means
absence only when this flag is true; missing/false metadata leaves existence
unknown. Outside the returned window, missing intervals establish no absence.
Neither empty status arrays nor event previews authorize final-snapshot replay.

An aggregated mark includes an opaque ID plus the canonical lane resource and
exact time envelope needed by the runnable demo's expansion endpoint:

```json
{
  "cluster_id": "clu_AQByZXYtMDE...",
  "lane_id": "control-plane/ROUTE/blue/203.0.113.0/24",
  "start_ns": "1759680003000000000",
  "end_ns": "1759680004000000000",
  "count": 142,
  "failure_count": 3,
  "detail_count": 2,
  "detail_truncated": true,
  "event_uids": ["event-401", "event-419"],
  "first_event_uid": "event-401",
  "last_event_uid": "event-442"
}
```

Expansion is offset-paginated in deterministic
`(timestamp_ns, source_sequence, event_uid)` order. The canonical `resource_id`
is the returned lane resource, and
`start_ns`/`end_ns` are the returned cluster envelope. `limit` is bounded to
1..200; `offset` is bounded to `0..9007199254740991`. Because these bounds
identify point events rather than a state-validity
interval, event instants equal to either envelope boundary are included. These
fields are submitted unchanged; clients must not derive resource
identity by parsing either `lane_id` or `cluster_id`:

```http
POST /v1/revisions/rev-01/timeline/clusters/detail
Content-Type: application/json
```

```json
{
  "resource_id": "control-plane/ROUTE/blue/203.0.113.0/24",
  "start_ns": "1759680003000000000",
  "end_ns": "1759680004000000000",
  "offset": 0,
  "limit": 100
}
```

```json
{
  "revision_id": "rev-01",
  "resource_id": "control-plane/ROUTE/blue/203.0.113.0/24",
  "start_ns": "1759680003000000000",
  "end_ns": "1759680004000000000",
  "offset": 0,
  "limit": 100,
  "total_count": 142,
  "items": [
    {
      "event_uid": "event-419",
      "time_ns": "1759680003015000000",
      "resource_id": "control-plane/ROUTE/blue/203.0.113.0/24",
      "effect_type": "modified",
      "state_changed": true,
      "outcome": "success"
    }
  ],
  "next_offset": 100,
  "truncated": true
}
```

`items` are the same redacted, plug-in-normalized per-resource marks used by
the timeline, not unprojected raw events. `next_offset: null` and
`truncated: false` identify the final page.

### Retained source records and regex lanes

Normalized events and source records are related streams, not one overloaded
record type. The generic source query can include CTF messages and non-CTF
inputs, whether or not a plug-in produced a domain event:

```http
POST /v1/revisions/rev-01/source-records/query
```

```json
{
  "start_ns": "1759680000000000000",
  "end_ns": "1759680010000000000",
  "source_types": ["ctf", "syslog"],
  "matched": false,
  "pattern": "ESI|mass withdraw",
  "offset": 0,
  "limit": 100
}
```

Each result has a stable `source_record_uid`, timestamp, source type/name,
record name, decoded message/attributes, and optional `matched_event_uid` plus
`matched_event_uids` for one-to-many normalization. A plug-in's private
`copy_text` is deliberately absent from this ordinary query.
Paging and ordering are core behavior. Source labels, decoding, normalization
links, and recommended regex presets belong to the selected plug-in.
`start_ns`, `end_ns`, and every retained source-record `timestamp_ns` use the
exact signed 64-bit nanosecond domain. Their grammar errors and lower/upper
range errors are reported distinctly. `offset` and `limit` accept only an
integer or canonical decimal-integer string. `offset` is enforced from zero
through JavaScript's exact-integer maximum (`9007199254740991`); `limit` is
enforced from 1 through 500. Values outside either range are rejected rather
than clamped, and every returned `offset`/`next_offset` JSON number is exactly
round-trippable by the browser.

A timeline query may include up to eight `record_lane_rules`:

```json
{
  "start_ns": "1759680000000000000",
  "end_ns": "1759680010000000000",
  "record_lane_rules": [
    {
      "lane_id": "unmatched-ctf",
      "label": "Unmatched CTF records",
      "pattern": ".+",
      "source_types": ["ctf"],
      "unmatched_only": true,
      "case_sensitive": false
    }
  ]
}
```

The response's `record_lanes` are separate from canonical resource lanes. Marks
carry `source_record_uid`, the compatible singular `matched_event_uid`, and
plural `matched_event_uids`, allowing deterministic timeline-to-log navigation
even when one retained input produced several events and the log uses virtual
scrolling. The core
limits pattern length and searched text and accepts only top-level alternatives
of literals, character classes, dot, anchors, and at most one `*`, `+`, or `?`
quantified atom per alternative. Groups, counted repetition, lookaround,
backreferences, unsupported escapes, and ambiguous/nested repetition are
rejected with no unsafe fallback. Lane and mark counts are capped.

### Windowed scale history

A scale bootstrap may replace embedded history arrays with an explicit
`history_transport.mode: "server-windowed"` descriptor. The bootstrap still
contains revision/timeline bounds, exact counts, the compact resource catalog,
and plug-in schemas, but `events` and `source_records` are empty. Clients must
use the advertised bounded endpoints instead of interpreting an empty array as
an empty capture. Non-scale revisions and topology-member snapshots may retain
their compatible embedded streams.

The combined virtual log query is:

```http
POST /v1/revisions/rev-01/event-log/query
```

```json
{
  "include_normalized": true,
  "source_types": ["ctf", "syslog"],
  "layers": ["control-plane"],
  "search": "mass withdraw",
  "start_ns": "1759680240000000000",
  "end_ns": "1759680250000000000",
  "offset": 0,
  "limit": 120,
  "locate": {"kind": "event", "uid": "event-50000"}
}
```

It returns exact `total_count`, `inside_count`, and `outside_count`; selected
range entries precede outside entries; every item has a stable zero-based
`display_index`; and `located_display_index` addresses data rows before clients
insert their own group headers. Ordering, range partitioning, pagination,
redaction-before-search, and locating are core responsibilities. Event,
resource, layer, and source-type values remain plug-in vocabulary.

Bulk log actions use query-scoped inclusive data-index ranges, not DOM rows or
thousands of client-retained IDs:

```http
POST /v1/revisions/rev-01/event-log/selection
```

```json
{
  "include_normalized": true,
  "source_types": ["ctf"],
  "layers": ["control-plane"],
  "search": "mass withdraw",
  "selection_ranges": [
    {"start": 120, "end": 132},
    {"start": 140, "end": 140}
  ]
}
```

The endpoint accepts at most 128 ranges and 5,000 selected data rows. It resolves
the same immutable revision/filter ordering and returns:

```json
{
  "revision_id": "rev-01",
  "selection_ranges": [{"start": 120, "end": 132}],
  "selection_count": 13,
  "items": [
    {
      "entry_id": "event:event-00120",
      "display_index": 120,
      "stream_kind": "event",
      "uid": "event-00120",
      "timestamp_ns": "1759680240120000000",
      "resource_ids": ["node-a/data-bridge/ETG/42"],
      "entry": {"event_uid": "event-00120", "event_type": "etg_modify"}
    }
  ],
  "copy_action_label": "Copy CTF text",
  "copy": {
    "items": [
      {
        "selection_id": "event:event-00120",
        "source_record_uid": "source-00120",
        "source_type": "ctf",
        "record_name": "etg_modify",
        "text": "[1759680240120000000] etg_modify { id = 42 }"
      }
    ],
    "item_count": 1,
    "total_bytes": 55,
    "omitted": [],
    "omitted_count": 0,
    "truncated": false
  }
}
```

Each `entry` is the same bounded/redacted projection used by the virtual log.
The `copy.items` array is ordered and deduplicated across singular/plural
source-to-event links. A fragment is a plug-in-supplied, already-redacted
`copy_text` value; core treats its contents as opaque, rejects non-strings,
NUL, and values over 65,536 UTF-8 bytes, and caps the response at 5,000
fragments and 1 MiB total. `copy.omitted` reports a `selection_id` and reason
such as `source_record_not_found`, `copy_text_unavailable`,
`invalid_copy_text`, or `copy_text_too_large`.

`copy_action_label` uses a plug-in label only when all copyable fragments
resolve to one declared source group; mixed/unknown groups use
`Copy plug-in text`. The hosting service authorizes the endpoint and the client
performs the actual clipboard write. Hide/show and review-marker actions in the
demo are browser-local presentation state; they do not mutate the immutable
revision. Core never assumes that a source type or group named `ctf` exists.

For immutable full-scale revisions, the core builds the literal-search corpus
after plug-in descriptors and sensitivity rules are final. Frontend-hosted
deployments do this synchronously on the first indexed search, under a visible
indexing progress operation; API-only startup performs the same bounded build
before serving. Each indexed document is the same case-folded, redacted
projection used for client search; raw plug-in payloads and sensitive values
never enter the corpus. Bounded result postings are reusable across virtual
pages and selected ranges. A successful event-only indexed response reports
`indexed_search: true`; if the configured serving bound is exceeded, the core
retains exact behavior through the compatible streaming fallback rather than
truncating counts.

The local demo persists only that safe projection in an immutable SQLite
sidecar. Its identity covers the packed archive content, search-projection
version, Python cache ABI, and Unicode case-folding data. Publication uses a
same-directory temporary database followed by atomic replacement; invalid,
incomplete, corrupt, or count-mismatched caches are rebuilt. SQLite result
postings remain an implementation detail—the production serving contract uses
the revision database and may implement literal candidates with PostgreSQL
`pg_trgm` followed by exact substring verification.

The demo may add an external-content, case-sensitive FTS5 trigram candidate index to
that sidecar. Its metadata records whether the revision uses `fts5-trigram` or
`sqlite-scan`; ordered safe-text digest, ordinal/size bounds, and a deterministic
candidate digest are checked before reuse, after a full source-aware FTS
integrity check at publication. The digest covers both the FTS vocabulary and a
small exception table for safe documents containing NUL. Those exception
ordinals are unioned into every FTS candidate set because older SQLite trigram
tokenizers may truncate text at NUL. `MATCH` never defines the result: every
candidate and exception still passes a parameterized
`instr(safe_text, search)` check, while empty, short, and parser-rejected needles
take the exact scan
path. Root `/health` exposes the non-sensitive serving state as
`history_search_backend` without disclosing the cache path or revision identity.
It remains available without an opened analysis session, reports
`analysis_ready=false` in that case, and includes the same durable worker/queue
projection as `/v1/control-plane/health`. Queue health includes state counts,
pending versus intentional `awaiting_selection` counts, oldest pending update,
stall threshold/count, bounded error class labels, and unexpected worker exits.
Nanosecond values are decimal strings. Either endpoint returns HTTP 200 with
`status="degraded"` for an observable unhealthy dependency so load balancers
can read the payload instead of receiving an unrelated session exception. The
shared health projection is total: a failing store/provider or malformed
counter becomes a stable bounded observation error, never private exception
text or an HTTP 500 from the health serializer.

The core browser uses a separate, non-cacheable load observation:

```http
GET /v1/analysis-load
```

Its closed `state` is `waiting`, `running`, `ready`, or `failed`; `stage` is one
of the generic core load stages. `completed` and `total` are JSON-safe
non-negative integers only when the active operation has a real total, and
`determinate` is then true. Otherwise both are null and the browser renders an
indeterminate progress bar. `records_processed` is an informational monotone
count, not a denominator. The response also contains a random operation ID,
bounded sequence/active-operation counts, decimal-string timestamps, and a
closed path-free `error_code`; it contains no input name, host path, plug-in
text, resource identity, or dump content. Both the node and multi-node pages
poll this same core endpoint only while an analysis request may cause a cold
revision load. Concurrent loads form one observation batch: the endpoint stays
`running` while any operation remains, and if any member fails the terminal
batch state is `failed` even when a sibling completes successfully. A later
non-overlapping load begins a fresh batch.

When the reusable frontend is enabled, ordinary runtime-v2 ingestion is
deferred to the first workspace request so this endpoint is reachable during
parsing. Lazy multi-node topology and route-provider construction is bound to
the same tracker. With `--api-only`, the default revision and safe search index
are loaded synchronously during lifespan startup; any ordinary failure crosses
the bounded startup boundary and process-control exceptions propagate
unchanged. Core does not use a detached warm-up worker or wait on one during
shutdown.

Service telemetry is not an HTTP response schema. Core emits a closed
`rda.operational.v1` record on `router_dump_analyzer.operations` for bounded
ingestion/catalog, worker, retention lifecycle, and control-plane access-denial
events. The handoff is
fixed-capacity and non-blocking, so records may be dropped and cannot be used
as durable progress. Fields exclude dump content, filesystem paths, tenant
labels, raw plug-in values, credentials/headers, concrete URLs, and exception
text. Access denials use closed phase/reason/route fields and are translated
exactly once without changing the HTTP response, including concealed scope
`404` responses. The allowed phase-to-reason pairs are:

- `request_source`: `host_rejected`, `origin_rejected`;
- `identity_verification`: `identity_verification_failed`;
- `identity_binding`: `tenant_required`, `tenant_binding_mismatch`,
  `principal_required`, `principal_binding_mismatch`;
- `role_authorization`: `required_role_missing`; and
- `scope_authorization`: `project_scope_denied`, `workspace_scope_denied`,
  `project_creation_scope_denied`, `workspace_creation_scope_denied`.

The decision constructor, reporter boundary, and event validator enforce this
closed vocabulary from one dependency-neutral core contract. Maintenance roles
are requested explicitly by their endpoints; a project/workspace named
`retention` does not change authorization for ordinary catalog operations.
A process-random HMAC derived only from a trusted resolved
tenant is optional within-run correlation and is never a sampling key. It is
included only when the bounded candidate algorithm's lower bound proves one
tenant is a strict majority of the current sample window; otherwise it is
omitted. This is a conservative proof, not a best guess.

Admitted sample keys are retained for the process lifetime. When their bounded
table is full, unseen keys share one permanent `sampling_scope="overflow"`
state instead of evicting an admitted key. Geometric/time coalescing is also
subject to an independent global token-bucket ceiling. Per-event suppression,
global suppression, overflow observations/emissions, invalid decisions, and
actual enqueue loss are accounted separately. Deployments configure standard
Python logging handlers/exporters; plug-ins do not define or emit this core
vocabulary, and upstream authentication remains the durable credential-audit
boundary.

Root and control-plane health add a payload-free `operational_events` object
containing process-local accepted, dropped, delivery-failure, queue
depth/capacity, and worker-liveness values. Any loss or delivery failure makes
that component and aggregate status degraded. The emitter never catches
`KeyboardInterrupt` or `SystemExit` at the producer boundary. Both health
routes intentionally require no tenant identity and expose only these
aggregate operational values—never project/workspace IDs, paths, event fields,
or exception text. Per-declared-event loss/suppression diagnostics remain
process-local and are not added to these anonymous responses.

The protected diagnostics projection is:

```http
GET /v1/control-plane/diagnostics/operational-events
```

```json
{
  "schema": "rda.operational-diagnostics.v1",
  "status": "ok",
  "operational_events": {
    "accepted_events": 12,
    "dropped_events": 0,
    "delivery_failures": 0,
    "queue_depth": 0,
    "queue_capacity": 1024,
    "worker_alive": true,
    "event_classes": [
      {
        "event": "control_plane.access.denied",
        "accepted_events": 2,
        "queue_full_drops": 0,
        "rejected_events": 0,
        "delivery_failures": 0
      },
      {
        "event": "control_plane.identity_resolver.response_headers_rejected",
        "accepted_events": 1,
        "queue_full_drops": 0,
        "rejected_events": 0,
        "delivery_failures": 0
      }
    ]
  },
  "access_denial_sampling": {
    "observed_denials": 8,
    "emitted_events": 2,
    "intentionally_suppressed": 6,
    "enqueue_failures": 0,
    "invalid_denials": 0,
    "admitted_keys": 3,
    "key_capacity": 1024,
    "overflow_observations": 0,
    "overflow_emitted_events": 0,
    "global_suppressed": 0
  }
}
```

The caller must resolve to `control-plane:instance-operator`; a tenant
`control-plane:admin` does not imply that role. The response sets
`Cache-Control: no-store`; snapshot failures return bounded `503`. The
`event_classes` array contains one row for every closed event name, not only
the example row. `status` is `degraded` when aggregate operational drops or
delivery failures, access-denial enqueue failures, or invalid denial objects
have been observed; otherwise it is `ok`. Counters above `2^53-1` are decimal
strings. The payload has two related but different scopes:
`operational_events` reads process-global emitter counters, while
`access_denial_sampling` reads the sampler installed on this ASGI app and
therefore aggregates every tenant handled by that app. It is an advisory,
concurrently moving snapshot that resets on restart. It contains no event
fields, tenant correlation, request data, or queue contents and is not a
durable security/compliance audit.

The visible density query is:

```http
POST /v1/revisions/rev-01/events/density/query
```

```json
{
  "start_ns": "1759680240000000000",
  "end_ns": "1759680250000000000",
  "bin_count": 240,
  "bin_start_index": 80,
  "bin_end_index": 160
}
```

The response contains only populated exact bins with inclusive nanosecond
bounds, total/failure counts, and the most frequent opaque plug-in event types.
`start_ns`, `end_ns`, and `bin_count` define one immutable global partition.
For inclusive span `S = end_ns - start_ns + 1` and effective resolution `k`,
bin `i` covers `start_ns + floor(S*i/k)` through
`start_ns + floor(S*(i+1)/k) - 1`, inclusive; every event is assigned to the
unique bin whose reported bounds contain its timestamp.
The optional `bin_start_index`/`bin_end_index` pair selects a half-open slice of
those global bin indices; both fields must be present together, the end must be
greater than the start, and one page may span at most 4,096 bins. Returned
`bins[].index` values remain global rather than page-relative, so adjacent or
overlapping pages have identical boundaries and counts even when the inclusive
time span is not evenly divisible by `bin_count`. When the pair is omitted, the
endpoint retains its compatible single-page form and caps the complete
partition to 4,096 bins. The core therefore caps one request's work and
response, while a client may retain an arbitrarily large logical zoom by
requesting only visible bins plus overscan.
For full-scale revisions the core answers from the normalized timestamp index
and may consume optional failure and event-type secondary indexes. Those
secondary indexes are accelerators, not additions to the public
`IndexedHistory` contract: an older conforming adapter without them receives a
one-pass derivation from its normalized indexed events and is never mutated.

## 7. Point-in-time resource tables and selected ranges

The generic table query is driven by plugin resource descriptors; the core does
not contain kind-specific columns:

```http
POST /v1/revisions/rev-01/resources/query
```

```json
{
  "time_ns": "1759680005000000000",
  "kinds": ["ETG", "ETE", "DTE", "GLUE"],
  "layers": ["data-bridge"],
  "search": "blue",
  "offset": 0,
  "limit": 200
}
```

`POST .../resources/query` and `GET .../resources/at` accept `offset` only in
`0..9007199254740991`. Indexed history and named table views apply pagination
and echo an exact numeric `offset` in that range. The legacy unindexed plain
table path is intentionally unpaged: it returns every matching row, ignores
`offset`/`limit` after HTTP validation, and omits pagination fields. Clients
requiring bounded pages must use indexed history or a named table view;
repeated offsets do not paginate the legacy response. `time_ns` instead uses
the signed 64-bit nanosecond domain. The generic HTTP integer adapter has no
timestamp defaults: every non-time field declares its own lower and upper
bounds.

Each item is a bounded resource-state row: canonical resource ID, descriptor
kind, layer, label, tri-state existence, status/status class, projected state
and key, interval validity bounds, quality, unknown fields, and the public
resource envelope. `source_event_uid` identifies the selected interval's
opening event when available; it is not a joined last-change record. These
rows do not join active relationships, failed-event history, or interval
provenance/evidence. Query relationships separately through the
[state-query surface](#3-state-query) with `include_relationships: true`.
Use the [timeline and cluster-detail surface](#6-timeline-and-cluster-expansion)
or `POST /v1/revisions/{revision_id}/event-log/query` in
[windowed scale history](#windowed-scale-history) for retained event details.
Resource `state` and typed `key` objects are allowlist projections: only fields
declared by that kind's `PropertyDescriptor` (or explicit `key_fields`) may
appear. `sensitive`, `client_visible: false`, and undeclared fields are omitted
recursively and cannot contribute to public search text. If such a property is
the kind's `condition_field`, returned status is `unknown`. This includes
private ancestors and relative paths within the condition path, even when a
descendant has its own public descriptor or uses a literal dotted key.
Dotted public/searchable fields and `display_name_fields` traverse nested
mappings, sequence elements, and literal dotted keys. Projection retains only
matching sequence elements in order, so their array indexes may change. A
public parent includes its subtree subject to privacy rules; unselected or
non-searchable sibling fields cannot contribute to resource search text.
Connector-like presentation comes from descriptor tags and never from a core
check for a resource name. An optional descriptor `icon` carries validated SVG
path geometry (`path`, four-number `view_box`, `render_mode`, and
`stroke_width`). Timeline lanes and graph nodes render it generically; graph
responses may echo the same icon on each node for clients that do not retain
the schema. Missing or invalid icons use the core fallback glyph.

The revision schema may include a `resource_table_views` array for bounded,
relationship-grouped tables. For example:

```json
{
  "view_id": "path-bundles",
  "label": "Path bundles",
  "root_kinds": ["ENCAP_GROUP"],
  "levels": [
    {
      "label": "Path",
      "relation_types": ["owns"],
      "target_kinds": ["ENCAP_ENTRY"],
      "direction": "outgoing"
    },
    {
      "label": "Next hop",
      "relation_types": ["next_hop"],
      "target_kinds": [],
      "direction": "outgoing"
    }
  ],
  "default_expanded_depth": 2,
  "max_roots": 100,
  "max_children_per_node": 16
}
```

A client selects it by sending `"view_id": "path-bundles"` to
`resources/query`. The response adds `view` and recursive `bundles`; each
node carries the normal resource-state envelope, the incoming relationship
interval, and bounded children. Only resources and edges active at `time_ns`
are included. The row type label, icon, presentation tags, and default fields
come from the referenced resource-kind descriptor. A plug-in can therefore use
the same mechanism for an interface-to-neighbor view (or any other resource
graph) without adding that vocabulary to the query API or browser renderer.

Resource kinds and relationship names above are illustrative
plug-in data—the core traversal has no built-in forwarding vocabulary.

The revision schema may also include a `dashboards` array. These are declarative
plugin-owned module definitions, not pre-rendered markup. A typical descriptor is:

```json
{
  "dashboard_id": "protocol-state",
  "title": "Protocol state",
  "description": "Protocol resources at the selected time.",
  "default_open": true,
  "collapsible": true,
  "default_expanded": false,
  "movable": true,
  "statistics": [
    {
      "statistic_id": "average-metric",
      "label": "Average metric",
      "aggregation": "average",
      "resource_kinds": ["ISIS_ADJACENCY"],
      "field": "state.metric",
      "precision": 1
    }
  ],
  "tables": [
    {
      "table_id": "protocol-objects",
      "title": "Protocol objects",
      "resource_kinds": ["ISIS_ADJACENCY", "EVPN_ROUTE"],
      "columns": [
        {"field": "label", "label": "Resource", "value_format": "resource"},
        {"field": "status", "label": "Status", "value_format": "status"}
      ],
      "max_rows": 50,
      "sort_field": "kind",
      "sort_direction": "ascending"
    }
  ]
}
```

Dashboard results are evaluated server-side over the complete point-in-time
population, rather than over whichever resource-table page happens to be visible:

```http
POST /v1/revisions/rev-01/dashboards/query
Content-Type: application/json
```

```json
{
  "time_ns": "1759680005000000000",
  "dashboard_ids": ["protocol-state"]
}
```

`time_ns` defaults to the revision capture time when omitted. Optional
`dashboard_ids` is an array of non-empty descriptor IDs; duplicate IDs are
removed while preserving request order. Omitting it evaluates every declared
dashboard, while an empty array evaluates none. A successful response is:

```json
{
  "revision_id": "rev-01",
  "time_ns": "1759680005000000000",
  "population_count": 247,
  "descriptor_errors": [],
  "dashboards": [
    {
      "dashboard_id": "protocol-state",
      "statistics": [
        {
          "statistic_id": "average-metric",
          "aggregation": "average",
          "value": 17.5,
          "matching_count": 42,
          "sample_count": 42
        }
      ],
      "tables": [
        {
          "table_id": "protocol-objects",
          "items": [],
          "total_count": 42,
          "returned_count": 0,
          "truncated": true
        }
      ]
    }
  ]
}
```

`population_count` is the number of authoritative temporal resource envelopes
the core evaluated for the selected declarations; table `total_count` is
computed before its plug-in-declared, core-bounded row cap. Field paths are safe
projections into the generic resource envelope, and aggregates and filter
operators come from fixed core enums. The plug-in owns dashboard IDs, resource
kinds, field paths, filters, columns, sorting, and aggregation declarations. The
core owns revision/time resolution, assembling the full temporal population,
safe declarative evaluation, redaction, and output bounds. The payload never
contains plug-in HTML, CSS, JavaScript, remote assets, or executable query
expressions. Module order and open/collapse choices are browser-local
preferences and are not revision data.
Comparison fields are bounded to 16 nested container levels, 1,024 items per
container, 4,096 comparison units, 65,536-character/byte atoms, and 4,096-bit
integers. Cyclic, unsupported, and over-bound values fail closed for filters and
are excluded from `count_distinct`; its `sample_count` counts comparable
values. Type-tagged non-finite floats remain comparable but are excluded from
numeric aggregates.

Field lookup is presence-aware. An explicit envelope null is present and wins
over state/key fallbacks; missing fields fail ordinary comparisons and are
omitted from projected table rows. `exists` defaults to testing for presence,
and explicit null participates in equality and `count_distinct`. Numeric
aggregates accept finite numbers only, excluding booleans and numeric strings.
An empty `sum` returns `0`; `average`, `minimum`, and `maximum` return null, and
each reports `sample_count: 0`. Table `max_rows` is an exact non-boolean integer
from 1 through 500.

`descriptor_errors` is empty for valid declarations. If an installed serialized
descriptor is malformed, the response remains bounded and contains no partially
evaluated dashboards:

```json
{
  "revision_id": "rev-01",
  "time_ns": "1759680005000000000",
  "population_count": 0,
  "dashboards": [],
  "descriptor_errors": [
    {
      "code": "invalid_dashboard_descriptor",
      "dashboard_id": "protocol-state",
      "path": "dashboards[0].tables[0].max_rows",
      "message": "dashboard table max_rows must be an integer between 1 and 500"
    }
  ]
}
```

The browser displays this failure instead of presenting an empty dashboard as a
successful query.

A range summary receives `[start_ns,end_ns)` and returns intersecting events,
intersecting status/lifecycle intervals, relationship add/remove mutations with
stable relationship and cause-event IDs, aggregate counts, and an optional diff
between the two endpoint worlds. A timeline query also returns relationship
validity spans clipped to the lifecycles of both endpoint resources. The point
cursor, pinned event, and selected range are independent client state; the
request does not imply that selecting a range clears either of the others.
While a range-summary request is pending or fails, the browser displays loading
or unavailable instead of deriving complete facts from its cache. Explicit node
snapshot mode labels a local summary as limited to loaded evidence.

## 8. Durable upload-coordinator plug-in selection and resume

The optional control plane implements durable upload/probe selection while the
plain core executable still supports one startup plug-in/input. Start the
API-only `router-dump-server`, start the browser server with
`--control-plane-dir`, or use `router-dump-ingest`; section 1.3 and
[`control-plane.md`](control-plane.md) are the exact route and operational
contract. These are core-owned routes, never plug-in-provided routes.

Candidate response records the probe set:

```json
{
  "import_id": "imp-01",
  "state": "awaiting_selection",
  "probe_set_hash": "sha256:<64 lowercase hex characters>",
  "candidates": [
    {"plugin_id": "router-family-2025", "plugin_version": "1.4.0", "package_hash": "package-sha256:<64 lowercase hex characters>", "instance_id": "router-family-2025.blue", "registered_execution_identity": "sha256:<64 lowercase hex characters>", "confidence": 0.94, "reasons": ["exact manifest platform"]}
  ]
}
```

Selection includes the current probe-set identity and exact package identity:

```json
{
  "probe_set_hash": "sha256:<64 lowercase hex characters>",
  "plugin_id": "router-family-2025",
  "plugin_version": "1.4.0",
  "package_hash": "package-sha256:<64 lowercase hex characters>",
  "instance_id": "router-family-2025.blue",
  "registered_execution_identity": "sha256:<64 lowercase hex characters>"
}
```

The request supplies `Idempotency-Key` as a required header. A stale probe set,
changed package identity, or conflicting repeated key returns `409`. The
selection receipt is durable: replaying the exact key and request returns the
current descriptor even after processing has advanced. A new key can confirm
the same stored exact identity but cannot replace it.
`instance_id` and `registered_execution_identity` MUST be supplied together.
They MAY both be omitted only for a legacy unambiguous candidate; configured
instances sharing ID, version, and package identity are ambiguous without the
pair and return `409`.
`POST .../resume` requeues only a failed job within its configured attempt
budget and returns the durable import descriptor. It restores `admitting` or
`publishing` when an exact staged catalog operation needs replay; publication
recovery never re-runs parsing.

The shown `package-sha256:` value is core's bounded digest of a complete
package import scope; `module-sha256:` is the corresponding top-level-module
form. A trusted loader may instead provide an immutable package/artifact
digest. All registries fail closed by default if none is
available. A manifest-only fallback requires the explicit local/test
`allow_manifest_identity=True` compatibility opt-out and is rejected by strict
durable headless/server execution. A descriptor-owned
`allow_inline_only=True` may admit it only as trusted-inline manifest authority.
Clients still treat `package_hash` as
opaque and echo the exact candidate field.

## 9. Errors and pagination

All non-success responses use:

```json
{
  "error": {
    "code": "capture_ranges_do_not_overlap",
    "message": "The selected observed resources do not support one common instant.",
    "retryable": false,
    "details": {"resource_ids": ["res-route-1", "res-hw-44"]},
    "correlation_id": "req-01J..."
  }
}
```

The structured envelope above is the production `/v1` target. The current
in-process FastAPI adapter still returns FastAPI's `{"detail": ...}` body for
some executable demo routes. That transitional body is core-owned
implementation debt, not a plug-in extension point: plug-ins must not construct
HTTP errors, and clients must not infer semantic error codes by parsing
`detail`. Migration is complete only when every route maps its typed core error
to the envelope above.

Required status mappings include `400 invalid_request`, `404 not_found`, `409`
for stale selection/revision conflicts, `413` for upload/result limits, `422`
for a semantically unsupported basis, unknown topology/status descriptor, or
unsupported projection/perspective combination, `429` for query budgets, and `503` only
for retryable infrastructure failures. A capped successful graph/timeline/state
query sets `truncated=true`; it never masquerades as a complete exact result.
