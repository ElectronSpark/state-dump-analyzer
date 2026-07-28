# API payload contract

Status: normative design fragment for `/v1`
Encoding: UTF-8 JSON; Arrow/Parquet exports use equivalent typed columns

The endpoint list in `architecture.md` is intentionally compact. This document
fixes the payload rules other tools need before implementation and should be
translated directly into Pydantic models/OpenAPI components.

## 1. Global rules

- Every analysis read is scoped to one immutable `revision_id`; a response that
  accepts `latest` resolves it once and returns the concrete ID.
- A `revision_id` is opaque and may contain `/`. Clients must URL-encode the
  complete ID when placing it in a revision-scoped URL and must not split it
  into path components. Servers expose path-aware
  `/v1/revisions/{revision_id}/...` routes so the decoded ID reaches revision
  lookup unchanged. The server binds revision-local data only after the router
  has parsed that path parameter; raw-path prefix matching is forbidden because
  overlapping IDs such as `a` and `a/inventory` are both valid.
- Nanosecond timestamps, counters that may exceed JavaScript's safe integer, and
  numeric key parts are decimal strings in JSON. Small counts and page sizes are
  ordinary JSON integers.
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
    "event_count": 125000,
    "matched_event_count": 125000,
    "resource_count": 7500,
    "source_record_count": 125000,
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
resource kind uses the conservative union of all declared sensitive fields.
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

Optional semantic hooks have an executable Python caller but no plug-in-owned
HTTP surface. Host code imports `PluginCapabilityExecutor` from
`router_dump_analyzer` and uses its `apply`, `revert`, `correlate`,
`check_consistency`, `project_topology`, `project_forwarding`, and
`resolve_forwarding_step` methods. The executor gates each call by the manifest,
bounds world reads and output iterators, validates requests and results against
the immutable schema, preserves recoverable diagnostics in typed result
envelopes, and raises a typed execution error for fatal or invalid output.
This makes the hook contract executable without implying that the current
runtime-v2 host has scheduled those hooks or exposed temporal, topology, or
route APIs; the providers above remain `None`.

Runtime-v2 ingestion also validates and retains scoped
`RelationshipCollectionObservation` markers as private normalized metadata.
Their collection-completeness inference is not yet materialized into the public
relationship intervals or API payloads in this document.

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

## 3. State query

Request:

```http
POST /v1/revisions/rev-01/state/query
Content-Type: application/json
```

```json
{
  "basis": {"kind": "reconstructed_time", "time_ns": "1759680003015000000"},
  "status_perspective_id": "hardware-observed",
  "resource_ids": ["res-route-1", "res-ete-b"],
  "include_relationships": true,
  "relation_types": ["depends_on", "references"],
  "page_size": 500,
  "cursor": null
}
```

Response:

```json
{
  "revision_id": "rev-01",
  "absolute_clock_domains": ["utc"],
  "status_perspective_id": "hardware-observed",
  "basis": {
    "kind": "reconstructed_time",
    "requested_time_ns": "1759680003015000000",
    "resolved_at_min_ns": "1759680003015000000",
    "resolved_at_max_ns": "1759680003015000000",
    "clock_domain": "normalized:revision",
    "provenance": "reconstructed",
    "quality": "best_effort"
  },
  "resources": [
    {
      "resource_id": "res-ete-b",
      "key": {
        "namespace": "synthetic",
        "node": "node-a",
        "layer": "data-bridge-layer",
        "kind": "ETE",
        "parts": [
          ["parent_resource_id", {"type": "uuid", "value": "123e4567-e89b-12d3-a456-426614174000"}],
          ["path_id", {"type": "uint64", "value": "7"}]
        ]
      },
      "exists": true,
      "properties": {"neighbor": "198.51.100.0"},
      "unknown_fields": [
        {"name": "program_state", "reason_code": "missing_before_value", "evidence_ids": ["ev-ete-update-4"]}
      ],
      "valid_from_ns": null,
      "valid_to_ns": "1759680003015000000",
      "provenance": "reconstructed",
      "quality": "unknown",
      "evidence_ids": ["ev-ete-update-4"]
    }
  ],
  "relationships": [
    {
      "relationship_id": "rel-22",
      "source_resource_id": "res-ete-b",
      "target_resource_id": "res-nbr-failed",
      "relation_type": "references",
      "attributes": {},
      "valid_from_ns": "1759680003015000000",
      "valid_to_ns": null,
      "provenance": "event_derived",
      "quality": "exact",
      "evidence_ids": ["ev-ete-update-4"]
    }
  ],
  "next_cursor": null,
  "truncated": false
}
```

The same endpoint accepts an absolute or relative selector from section 2 and
returns the resolved basis, including all per-node mappings. Resource rows use
the generic envelope regardless of plugin kind: canonical typed key, tri-state
`exists`, plugin properties, field-level unknowns, validity/capture ranges,
provenance, quality, and evidence. Relationship rows are the same time-valid
typed edges used by graph and topology projections.

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
  "cursor": null
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
perspective IDs, a page size, and an opaque cursor. The response streams ordered
resource existence/status changes and inferred-connectivity add/remove/status
changes. Every change carries its node-local effective range, normalized
absolute range when supported, uncertainty, before/after value, cause/evidence,
provenance, and quality. Pagination is revision/query-bound; replaying all pages
must produce the same snapshot as `topology/query` at the end basis.
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
stable ordering, coverage, comparison, and navigation. The federation linker
owns inter-node boundary and endpoint-attachment matches and their candidate
evidence; it does not reinterpret a node plug-in's split-horizon or local
delivery decision.

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
1..200. Because these bounds identify point events rather than a state-validity
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

For immutable full-scale revisions, the core may build the literal-search
corpus in the background after plug-in descriptors and sensitivity rules are
final. Each indexed document is the same case-folded, redacted projection used
for client search; raw plug-in payloads and sensitive values never enter the
corpus. Bounded result postings are reusable across virtual pages and selected
ranges. A successful event-only indexed response reports
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
path. `/health` exposes the non-sensitive serving state as
`history_search_backend` without disclosing the cache path or revision identity.

The visible density query is:

```http
POST /v1/revisions/rev-01/events/density/query
```

```json
{
  "start_ns": "1759680240000000000",
  "end_ns": "1759680250000000000",
  "bin_count": 240
}
```

The response contains only populated exact bins with inclusive nanosecond
bounds, total/failure counts, and the most frequent opaque plug-in event types.
The core caps one request's work and response, while a client may retain an
arbitrarily large logical zoom by requesting only visible bins plus overscan.
For full-scale revisions the core answers from timestamp, failure, and
event-type indexes; it does not rescan or serialize the 100K-event stream.

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
  "limit": 200
}
```

Every item includes its canonical resource ID, descriptor kind, existence and
status at the requested time, active typed relationships, last accepted change,
failed events that did not change state, provenance, quality, and evidence.
Resource `state` and typed `key` objects are allowlist projections: only fields
declared by that kind's `PropertyDescriptor` (or explicit `key_fields`) may
appear. `sensitive`, `client_visible: false`, and undeclared fields are omitted
recursively and cannot contribute to public search text. If such a property is
the kind's `condition_field`, returned status is `unknown`.
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

## 8. Future upload-coordinator plug-in selection and resume

The current core executable selects one plug-in before application startup with
`--plugin` or `--plugin-module` and opens the explicit `--input` path. The
payloads below specify a future durable upload/probe coordinator; they are not a
plug-in-provided route and are not required by the current single-runtime
command.

Candidate response records the probe set:

```json
{
  "import_id": "imp-01",
  "state": "awaiting_selection",
  "inventory_hash": "sha256:...",
  "probe_set_hash": "sha256:...",
  "candidates": [
    {"plugin_id": "router-family-2025", "plugin_version": "1.4.0", "package_hash": "sha256:...", "confidence": 0.94, "reasons": ["exact manifest platform"]}
  ]
}
```

Selection includes optimistic-concurrency identity and an idempotency key:

```json
{
  "probe_set_hash": "sha256:...",
  "plugin_id": "router-family-2025",
  "plugin_version": "1.4.0",
  "package_hash": "sha256:...",
  "idempotency_key": "select-imp-01-attempt-1"
}
```

A stale selection returns `409 stale_probe_set`. `POST .../resume` is idempotent
and returns the durable job resource.

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

Required status mappings include `400 invalid_request`, `404 not_found`, `409`
for stale selection/revision conflicts, `413` for upload/result limits, `422`
for a semantically unsupported basis, unknown topology/status descriptor, or
unsupported projection/perspective combination, `429` for query budgets, and `503` only
for retryable infrastructure failures. A capped successful graph/timeline/state
query sets `truncated=true`; it never masquerades as a complete exact result.
