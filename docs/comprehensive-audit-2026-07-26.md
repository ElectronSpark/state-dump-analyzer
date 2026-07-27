# Comprehensive security, correctness, and ownership audit — 2026-07-26

## Status and scope

This record captures the remediation of the independent 2026-07-26 audit
performed against the real generated multi-node assembly. The source audit
reported a baseline of **1 failed, 580 passed, 3 skipped, and 2,895 passing
subtests**. The work was checkpointed in commit `1471123` before remediation.

The labels below are intentional:

- **Fixed and validated** means the finding has a regression test and passed
  the final local validation matrix.
- **Mitigated and guarded** means new coupling is prevented, while a known
  compatibility path still needs structural replacement.
- **Deferred structural work** is not represented as complete.

This is an engineering audit record, not a claim that the prototype is ready
for untrusted public deployment or arbitrary production plug-ins.

## Outcome

The four critical findings are closed: user-supplied record matching is limited
to a deterministic regex subset; client data is constructed through explicit
allowlists with recursive redaction; revision scope uses Starlette's parsed
route parameter; and plug-in colors cannot become markup. The SQLite NUL/FTS
false-negative, temporal ordering and uncertainty defects, route loop and
availability errors, typed-identity collisions, and the reported standalone
generator boundary failures are also covered by regressions.

A 2026-07-27 follow-up tightened the same boundaries under adversarial
collisions, nested/re-keyed payloads, local-only clocks, adjacent history
windows, compatibility route executors, conflicting federation claims, and
generator propagation cadence. The fixed rows below include that regression
evidence; the baseline counts above remain the historical 2026-07-26 run,
while the validation matrix below is refreshed after the follow-up.

The browser-facing demo schema now explicitly declares every client-visible
resource property. The core remains fail-closed: undeclared kinds and
properties do not become visible merely because a demo emitted them.

The largest remaining risks are structural rather than hidden in this result:
the route coordinator is still a large mutable-dictionary pipeline, and the
browser has not yet moved to TypeScript or markup-by-construction rendering.
Executable migration guards prevent those compatibility areas from growing.

## Fixed and validated findings

| Finding | Remediation | Ownership boundary | Regression evidence |
|---|---|---|---|
| Unauthenticated ReDoS through source queries and timeline lane rules | Both paths use one compiler for a strict, deterministic subset: alternatives of literals, character classes, dot, anchors, and at most one quantified atom per branch. Groups, counted repetition, backreferences, and ambiguous constructs are rejected before matching. | Core validates and executes bounded query mechanics; plug-ins may only declare patterns accepted by that contract. | `test_source_record_core.py`, `test_plugin_api.py` |
| Nested sensitive fields, re-keying, and core-envelope collisions | Client payloads retain a fixed core envelope while descriptor rules apply only inside plug-in property containers. Dotted rules cover nested mappings/lists and literal dotted keys. Typed metadata and nested event subject/effect allowlists reject extension-bag and scalar-container smuggling. Event policies use explicit resource kinds plus all resolvable canonical affected-resource IDs; generic event `kind` is never mistaken for resource type, and unresolved kinds fail closed. The seeded 32-case adversarial matrix checks bootstrap, event, resource, and range projections under nesting, re-keying, and collisions. | Plug-ins declare sensitivity and visibility; core resolves affected resource identity and enforces one scoped publication boundary. | `test_resource_property_policy.py`, `test_normalized_data_service.py`, `test_event_query_redaction.py`, `test_frontend_security.py` |
| Sensitive conditions or values promoted into status and histogram keys | Non-client-visible or sensitive condition fields yield `unknown`; range details and aggregate keys use the same redaction policy. | Core projection and aggregation. | `test_normalized_data_service.py`, `test_event_query_redaction.py` |
| Raw-path revision confusion | Revision scope is entered by an `APIRouter` dependency using the already-parsed `revision_id`; raw prefix matching was removed. | Core HTTP routing. | `test_runtime_revision_scope.py` |
| Plug-in layer-color XSS and missing browser policy headers | Colors are validated as `#RRGGBB` with a deterministic safe fallback in both Python and JavaScript. The web app emits CSP, frame, referrer, and content-type protections. | Core validates presentation primitives; browser renders only validated values. | `test_frontend_security.py`, `test_core_web_app.py`, live header smoke |
| FTS5 false negatives after U+0000 | The sidecar format tracks NUL-bearing ordinals and unions them into candidate sets before exact `instr` verification. The sidecar digest includes that exception set. | Core history index. | `test_history_search_core.py` |
| Same-timestamp replay, resurrection, and boundary duplication | Replay orders by timestamp and `source_sequence`; a modify after delete updates latent state without recreating the resource; no exact historical claim is made before evidence exists. Change queries use `[start_ns,end_ns)` for both resource events and relationship mutations, so an adjacent-window boundary appears once in the later window. | Core temporal reducer. | `test_temporal_boundaries.py`, `test_multi_node_topology.py` |
| Multi-node uncertainty and unscoped relative anchors | The coordinator samples the complete bounded uncertainty interval, including transitions, and preserves ambiguity. Explicit perspective/projection watermarks are qualified by immutable member/revision/plug-in context and can resolve local-only time without a wall clock. The old capture-minus-lag path is retained only as a labeled `legacy_capture_lag` fallback. | Core temporal/topology coordination; providers declare completeness watermarks. | `test_multi_node_topology.py` |
| Conflicting link types depended on claim order | A paired-claim disagreement returns deterministic `link_type: "unknown"`, sorted `claimed_link_types`, unknown operational status, and `plugin_link_type_mismatch`; presentation-role conflicts also fail closed. | Federation plug-ins declare claims; core validates and makes conflicts deterministic. | `test_multi_node_topology.py` |
| Route loops could still resolve or incomplete identity could look cyclic | Exact complete-state cycles terminate or truncate the candidate and remain unresolved. Compatibility traversal identity defaults incomplete; repeated incomplete opaque keys do not mark occurrences repeated or prove a cycle. Derived hop and recursion counters are checked rather than trusting plug-in indices. | Core traversal safety. | `test_multi_node_route.py`, `test_multi_node_route_regressions.py` |
| Withdrawn attachments, count-only ECMP, and ambiguous legacy mode omission | Destination attachments carry explicit availability; withdrawn paths do not become available endpoints. ECMP requires explicit all-active semantics. A legacy executor may omit `multipath_mode` only with at most one selected candidate, normalized to `single_active`; multiple selected candidates fail validation. Candidate, segment, hop, and recursion limits are enforced. | Plug-ins declare forwarding state; core validates and traverses it. | `test_multi_node_route.py` |
| Reversed fixed flows used the executor's original direction labels | A fixed endpoint-pair executor accepts the same pair in either order by selecting the opposite internal directional declarations while preserving caller-facing direction. Reachability is checked against that trace's actual directional destination, including a presented service endpoint on the return trace. The counterpart reverses the caller's flow, and ambiguous multi-attachment reversal fails closed. | Core maps caller flow/direction; plug-ins own fixed scenario candidates and attachment declarations. | `test_multi_node_route.py`, `test_multi_node_route_regressions.py` |
| Core invented VRF/CIDR semantics | Missing VRFs stay missing, and the core no longer parses opaque prefixes to manufacture endpoint aliases. | Node plug-ins own network meaning; core owns generic traversal. | `test_node_semantic_boundaries.py`, route regressions |
| Typed-key collisions and inconsistent encoders | `canonical.py` is the single bounded typed-value encoder. `ResourceKey` accepts 1–32 unique named typed parts, preserves UUID/bytes/integers, and rejects floats, booleans, unordered mappings, arbitrary objects, and ambiguous containers. Policy scopes preserve explicit ordered arguments. | Core identity and wire integrity. | `test_canonical.py`, `test_plugin_api.py` |
| Generator leaked authoring topology, implicitly promoted attachment properties, or truncated delayed propagation | Export crosses only an explicit `node_local_observation` status/property envelope; the browser save writes the same canonical envelope, top-level resource/local-resource/port fields are identity fallback rather than evidence, and all other attachment properties stay private. Exact private medium values are rejected in built-in and plug-in-defined identity fields (`*_id[s]`, `*_key[s]`) without scanning ordinary status/text values. History is ordered by timestamp and source sequence. Capture validation uses the actual eligible-target cadence horizon (parallel, serial, or two-target waves) plus jitter, warns when observations would fall after capture, and excludes those observations from the dump. Node clocks apply to final state, capture, and logs; failed propagation remains failed. | Standalone generator owns authoring/simulation; node dumps contain only explicit local evidence. | `state-dump-generator/tests/test_model.py`, `test_simulation.py`, `test_archive.py` |
| Generator HTTP desynchronization and ineffective link guards | Request bodies use bounded timed reads and close on early rejection. Path validation checks symlinks/junctions before resolution and keeps targets inside the selected root. | Standalone generator security boundary. | `state-dump-generator/tests/test_server.py`, `test_archive.py` |
| Generic demo package names | `demo/plugin` and `demo/generator` were replaced by `rsl_demo_plugin` and `rsl_demo_generator`; the entry point is `rsl_demo_plugin:plugin`. Core does not import the demo. | Demo distribution. | Distribution, package-boundary, and source-deduplication tests |
| No automated quality gate | CI now runs the core/demo/generator suites on Windows and Linux, frontend checks on Node 22, targeted Ruff and mypy checks, launcher syntax checks, and clean-build distribution/import/resource smoke tests. | Repository delivery. | `.github/workflows/ci.yml`; local equivalent checks below |

## Client-visible resource schema

Allowlist projection exposed a real omission in the demo: most generated kinds
had table-field hints but no property declarations. Weakening the core would
have reopened the sensitive-data finding. Instead, the generated demo schema
now explicitly declares the intended public fields for ETG, ETE, DTE, EVPN
Ethernet Segment, Virtual Interface, Neighbor, IP routing, IP route, and
adjacency resources.

The demo keeps `source_resource_id`, `source_scenario_id`, and `updated_at_ns`
server-side. A schema test requires every display, table, timeline, and
condition field to be either a declared property or key. A live browser check
confirmed that route `next_hop` remained visible while those provenance names
were absent from the page DOM.

## Validation evidence

The final local matrix after remediation was:

| Check | Result |
|---|---|
| Root `unittest` discovery | **633 passed, 3 skipped** |
| Demo plug-in test discovery | **16 passed** |
| Standalone generator discovery | **44 passed, 3 skipped**; Windows symlink-creation privilege was unavailable |
| Plug-in author documentation/package/boundary smoke | **43 passed** |
| Demo conformance fixture | Passed |
| Python `compileall` across all source and test trees | Passed |
| Ruff `E9,F63,F7,F82` gate | Passed |
| mypy over `canonical.py`, `route_trace_core.py`, and `topology_core.py` | Passed |
| Frontend contract plus `node --test` | **4 passed** |
| Core and demo wheel builds and installed-resource/entry-point inspection | Passed |
| Full-scale launch preflight | Passed in 86.8 s after the schema fingerprint changed |
| Live server health | 10 nodes; 125,001+ events and 7,502–7,506 resources per node |
| Live browser smoke | Fabric, focused/all-path route views, route tables, timeline, resource tables, temporal correlation, and normalized log loaded without console errors |
| Live response headers | CSP, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and `X-Content-Type-Options: nosniff` present |
| `git diff --check` | Passed; only Windows line-ending notices |

The live node workspace reported 125,005 exact server-windowed events, 7,504
resources, 180 density bins, and two plug-in-defined unmatched-log lanes.
Selecting the IP-route resource table showed the declared VRF, protocol, and
next-hop values.

## Mitigated and executable migration guards

`test_node_semantic_boundaries.py` AST-scans executable core code for demo,
vendor, and protocol vocabulary. New ownership violations fail the suite.

Two existing compatibility areas have exact, shrinking-only budgets:

- legacy demo bootstrap fields still transported by `normalized_data.py`; and
- `_generated_` compatibility identifiers/literals in the route coordinator.

These guards stop new coupling and make removal measurable. They do not make
the remaining code generic by assertion. The rationale and exit conditions are
recorded in [Architecture and library decisions](architecture.md).

## Deferred structural work

The following recommendations remain open:

1. Replace the large mutable-dictionary route pipeline with typed
   `RouteTraceRequest`/`RouteTraceResult` values and pure transforms, then
   remove the remaining generated-projection compatibility branch.
2. Move the browser toward TypeScript and escaping-by-construction markup.
   The current Node suite covers the first pure helpers, not the two complete
   application modules.
3. Remove the remaining demo bootstrap compatibility envelope from
   `normalized_data.py`.
4. Complete the typed admission and persistence gateway described in the
   [core/plug-in boundary audit](core-plugin-boundary-audit-2026-07-22.md).
5. Retire browser-side semantic fallbacks as authoritative server endpoints
   replace them.
6. Expand mypy and Ruff coverage beyond the current high-value boundary.
7. If richer regular expressions become necessary, add an explicitly bounded
   engine without weakening the safe subset used by the public endpoints.

The packet IR and advanced scenario boundary remain documented in the
[advanced route-trace audit](advanced-route-trace-audit-2026-07-25.md).

## Previously verified strengths

The source audit also reported stable pagination, deterministic timeline
queries, clean 24-way concurrent load, reproducible seeded fixtures, effective
path-traversal rejection, and correct integer-nanosecond handling. This
remediation did not replace those protections. The final suite and browser
smoke revalidated the affected pagination, timeline, fixture, and integer
paths; the other statements remain attributed to the source audit.

## Readiness conclusion

The reported exploitable server and projection failures are fixed and guarded
by tests. The demo is again launchable against the full generated assembly,
with a fail-closed core and explicit plug-in-owned public schema.

The repository is suitable for continued controlled development and design
review. Production hardening still depends on the deferred typed route
transport, admission/persistence gateway, broader static analysis, and a more
structurally safe frontend rendering model.
