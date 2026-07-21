# API payload contract

Status: normative design fragment for `/v1`
Encoding: UTF-8 JSON; Arrow/Parquet exports use equivalent typed columns

The endpoint list in `architecture.md` is intentionally compact. This document
fixes the payload rules other tools need before implementation and should be
translated directly into Pydantic models/OpenAPI components.

## 1. Global rules

- Every analysis read is scoped to one immutable `revision_id`; a response that
  accepts `latest` resolves it once and returns the concrete ID.
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
- Page cursors and cluster IDs are opaque, revision/query-bound strings. Clients
  must not parse them.

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

## 3. State query

Request:

```http
POST /v1/revisions/rev-01/state/query
Content-Type: application/json
```

```json
{
  "basis": {"kind": "reconstructed_time", "time_ns": "1759680003015000000"},
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
        "parts": [["etg", {"type": "string", "value": "etg-100"}], ["id", {"type": "string", "value": "ete-b"}]]
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

## 4. Route resolution

Request:

```json
{
  "basis": {"kind": "reconstructed_time", "time_ns": "1759680005000000000"},
  "vrf_resource_id": "res-vrf-blue",
  "destination": "203.0.113.42",
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

`result` is `resolved`, `partially_resolved`, `unresolved`, or `cycle`. A cycle
is a normal bounded result, not an HTTP 500.

## 5. Timeline and cluster expansion

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

An aggregated mark includes an opaque expansion handle:

```json
{
  "kind": "event_cluster",
  "cluster_id": "clu_AQByZXYtMDE...",
  "lane_id": "lane-route-1",
  "start_ns": "1759680003000000000",
  "end_ns": "1759680004000000000",
  "counts": {"total": 42, "failure": 3, "unknown": 1},
  "representative_event_ids": ["event-401", "event-419"]
}
```

Expansion is cursor-paginated in deterministic source order:

```http
GET /v1/revisions/rev-01/timeline/clusters/clu_AQByZXYtMDE.../events?cursor=cur_AAE...
```

```json
{
  "revision_id": "rev-01",
  "cluster_id": "clu_AQByZXYtMDE...",
  "events": [{"event_id": "event-419", "timestamp_ns": "1759680003015000000", "source_sequence": 4}],
  "next_cursor": null,
  "truncated": false
}
```

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
record name, decoded message/attributes, and optional `matched_event_uid`.
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
carry `source_record_uid` and `matched_event_uid`, allowing deterministic
timeline-to-log navigation even when the log uses virtual scrolling. The core
limits pattern length and searched text, rejects lookarounds/backreferences and
unsafe repeated quantifiers, and caps lane and mark counts.

## 6. Point-in-time resource tables and selected ranges

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
Connector-like presentation comes from descriptor tags and never from a core
check for a resource name. An optional descriptor `icon` carries validated SVG
path geometry (`path`, four-number `view_box`, `render_mode`, and
`stroke_width`). Timeline lanes and graph nodes render it generically; graph
responses may echo the same icon on each node for clients that do not retain
the schema. Missing or invalid icons use the core fallback glyph.

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

The client evaluates each descriptor over the same `resources/query` response
for the selected `time_ns`. Field paths are validated projections into the
generic resource envelope, aggregates and filter operators come from fixed core
enums, and row limits are bounded. The payload never contains plugin HTML, CSS,
JavaScript, remote assets, or executable query expressions. Module order and
open/collapse choices are browser-local preferences and are not revision data.

A range summary receives `[start_ns,end_ns)` and returns intersecting events,
intersecting status/lifecycle intervals, relationship add/remove mutations with
stable relationship and cause-event IDs, aggregate counts, and an optional diff
between the two endpoint worlds. A timeline query also returns relationship
validity spans clipped to the lifecycles of both endpoint resources. The point
cursor, pinned event, and selected range are independent client state; the
request does not imply that selecting a range clears either of the others.

## 7. Plugin selection and resume

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

## 8. Errors and pagination

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
for a semantically unsupported basis, `429` for query budgets, and `503` only
for retryable infrastructure failures. A capped successful graph/timeline/state
query sets `truncated=true`; it never masquerades as a complete exact result.
