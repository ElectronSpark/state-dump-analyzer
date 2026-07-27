# Core, plug-in, and federation boundary audit

Date: 2026-07-22
Scope: the executable contract, demo server/data adapters, and browser shell

## Outcome

The canonical model is mostly generic, but several demo conveniences currently
sit in code that behaves like the core controller or browser shell. The most
important violations are parsing opaque resource IDs, inferring normalized
condition classes from device text, and hard-coding CTF-versus-external source
groups in the browser.

Use this three-owner rule for every migration:

1. **Core** owns trust boundaries and mechanics: safe inventory/materialization,
   canonical envelopes and identity, clock transforms, interval reconstruction,
   persistence, budgets, APIs, orchestration, and generic rendering.
2. **Node/device plug-ins** own facts whose meaning varies by platform, release,
   layer, or protocol: parsers, typed keys, labels/icons, status normalization,
   mutations, local correlations, forwarding projection, local topology
   projection, and declarative dashboards.
3. **Federation/linker plug-ins** own cross-node inference over bounded,
   normalized claims: peer/domain matching, corroboration, ambiguity policy, and
   inter-node link semantics. They do not read raw device artifacts or replace a
   node plug-in's state.

If a decision needs a resource-kind name, a key-field name, a vendor status
token, or protocol knowledge, it is not core behavior. If it matches claims
from different members, it belongs to the federation/linker. Everything else
must still pass through core validation, temporal selection, and query budgets.

## Revised execution shape

The intended runtime is a pair of typed gateways around untrusted semantic
code:

1. The core inventories and safely materializes artifacts. A node plug-in sees
   only bounded readers or dependency-free decoder records.
2. The node plug-in emits typed observations, events, `ChangeSet` mutations,
   descriptors, and local forwarding/topology projections.
3. The core validates every emitted batch, qualifies local identifiers with the
   plug-in instance and schema digest, assigns canonical identity, materializes
   temporal intervals, and stores an immutable revision.
4. Core query engines resolve clocks and time selectors, enforce budgets, and
   return generic envelopes. They do not reinterpret plug-in vocabulary.
5. A federation/linker plug-in may consume only bounded normalized claims from
   frozen member revisions. Its output passes through another core validation
   gateway before becoming assembly topology or cross-node path data.
6. The browser renders validated descriptors and normalized result enums. It
   may perform layout, brushing, zooming, virtualization, and selection, but
   not parsing, reduction, route inference, topology reconstruction, or
   cross-node matching.

This shape deliberately separates the *semantic producer* from the *integrity
authority*. A plug-in decides what a device fact means; the core decides whether
that fact is structurally valid, bounded, temporally coherent, and safe to
publish.

## Prioritized findings

| Priority | Finding and current evidence | Target owner | Migration status |
|---|---|---|---|
| P0 | The executable demo still moves many plug-in results as nested dictionaries rather than admitting all results through one typed `Observation`/`DomainEvent`/`ChangeSet` validation gateway. A malformed or undeclared semantic record can therefore reach demo-specific materializers through a path the production design forbids. | Core coordinator owns batch validation and schema/reference checks; plug-ins own only typed output construction. | **Pending structural migration.** Keep the current adapter for the runnable fixture, but put a single typed admission port in front of persistence before treating the demo server as a production reference. |
| P0 | The demo controller parsed opaque IDs and recognized router kinds while deriving layer, kind, and labels. | Node/device plug-in supplies canonical fields and descriptors; the core may show only the opaque literal as fallback. | **Migrated.** The controller helpers were removed, the node-workspace adapter preserves literal IDs/unknowns, and boundary tests reject semantic ID parsing and invented labels/status. |
| P0 | The scale loader inferred condition classes by substring-searching vendor-like status text. | Packed-demo plug-in emits an exact normalized condition class; missing normalization remains `unknown`. | **Migrated.** Exact fixture vocabulary now lives in `demo/rsl_demo_plugin/scale.py`; deceptive strings such as `vendor-failover-ready` remain unknown. |
| P0 | The browser hard-coded `ctf` and `external` source buckets and inferred membership from source vocabulary. | Node/device plug-in declares opaque source groups and assigns source types; core validates references; browser renders controls generically. | **Migrated.** `SourceRecordGroupDescriptor` and `PluginSchema.source_record_groups` are executable, fixtures declare both demo groups, and the fixed browser controls were replaced with descriptor-driven controls. |
| P0 | Untimed retained records were placed at epoch zero, and timeline lane marks embedded the entire retained/raw record. | Core owns time placement, bounded projections, and the API privacy boundary. | **Migrated for timeline/range paths.** Untimed records are reported as unplaced, invalid timestamps fail clearly, and lane marks expose only a capped generic navigation/display projection. A broader source-detail/redaction policy remains below. |
| P0 | Equal local status-perspective IDs from different plug-in installations or schema revisions could be conflated. | Core qualifies plug-in-owned local IDs when crossing revision/query boundaries. | **Migrated in the contract.** `StatusPerspectiveRef` carries the local ID plus optional plug-in-instance and schema-digest qualifiers across observations, mutations, views, and `ReadOnlyWorld`. Runtime persistence still needs to enforce qualification at admission. |
| P1 | Route rendering inferred active/dead/control-plane/consistency state from missing booleans and human reason or finding text. | Node/forwarding plug-ins emit normalized route/path enums and resolution contributions; the browser maps only explicit normalized fields to presentation. | **Migrated in the route UI.** Missing values remain unknown, exact enum aliases are the only compatibility path, and absent installation/activity fields no longer render as false. |
| P1 | The generic browser embedded router acronyms and protocol spelling in `RESOURCE_TYPE_ACRONYMS`. | `ResourceKindDescriptor.display_name`; literal kind ID is the non-semantic fallback. | **Migrated.** The acronym table is gone and a boundary test uses unrelated vocabulary. |
| P1 | Scale labels, key interpretation, icons, dashboards, capabilities, and initial walkthrough choices lived in the packed-data loader. | Packed-demo plug-in/fixture adapter. | **Migrated.** These policies now live in `demo/rsl_demo_plugin/scale.py`; the demo-only `scale_data.py` loads/indexes their declared output. |
| P1 | The small fixture generator repeated kind-aware ID labels and relationship presentation. | Demo fixture plug-in. | **Migrated.** Compatibility semantics now live in the standalone example plug-in package, outside generic query/controller code. |
| P1 | Dashboard filtering flattened value types, counted unknown existence as present, rounded large integers through floating point, and returned undeclared row fields. | Core owns exact declarative evaluation and bounded projection; plug-ins own descriptors only. | **Migrated.** `dashboard_core.py` preserves scalar types, tri-state existence, exact integers, and the core envelope plus declared columns. |
| P1 | The single-node browser still contains `localTopologyQuery`/`localTopologyEvents`, which reconstruct temporal topology and changes when the API is unavailable. It also synthesizes fallback topology capabilities from loaded resource layers. | Core query service plus node plug-in topology projector. The browser may display an explicit unavailable/partial result but must not become a second reducer/projector. | **Pending.** Replace the fallback with a node-scoped server endpoint or a plug-in-emitted, already-normalized snapshot; fail closed when neither exists. |
| P1 | The browser derives lifecycle/status intervals from event effect strings and invents an all-time lifecycle when no interval was supplied; the packed scale path contains another reducer with additional compatibility verbs. | Plug-in maps source vocabulary to typed `MutationOperation`/`ResourceEffect`; one core temporal reducer materializes intervals; browser renders them. | **Pending.** Remove `deriveLaneIntervals` semantic reconstruction after all fixture and node-snapshot paths return canonical intervals. Keep compatibility verb mapping only in the fixture plug-in. |
| P1 | The main topology browser derives domain keys from heterogeneous payload fields, groups them in unscoped maps, synthesizes missing domain state/roles, and can attach pairwise links to those inferred domains. | Node plug-ins emit local domain/attachment claims; federation/linker matches qualified claims; core returns canonical domains/memberships/match state; browser performs layout only. | **Pending.** Move domain normalization and matching behind the typed federation gateway, then delete browser grouping/inference. Text-regex node/link health inference must likewise become explicit condition classes from producers. |
| P1 | The browser retains a second dashboard evaluator for local fixture fallback. Its field traversal/filter semantics can drift from `dashboard_core.py`. | Core evaluates descriptors against an authoritative temporal population; browser renders returned modules. | **Pending.** Remove browser evaluation after every supported node/scale mode exposes the bounded dashboard query endpoint. |
| P1 | Forwarding and cross-node federation were described extensively but did not have equally explicit, separate request/result protocols. | Node plug-ins contribute local forwarding semantics; core resolves generic paths; federation/linker plug-ins connect frozen member claims without raw-artifact access. | **Migrated in the executable contract.** `ForwardingProjectionRequest`, explicit path-group/member state, and bounded `ResolutionContribution` cover local projection; typed connector claims, qualified global references, match policies/results, and a separate `FederationLinkerPlugin` cover assembly matching. Runtime admission/persistence remains part of the P0 gateway migration. |
| P1 | The forwarding IR is typed, but the route-trace result transported to the browser is still an untyped demo dictionary with a large parallel vocabulary for path activity, selection, disposition, completeness, and consistency. | Core route engine owns the stable trace request/result/candidate/segment enums; plug-ins contribute forwarding records and referenced explanation text. | **Pending.** Add typed `RouteTraceRequest` and `RouteTraceResult` families before treating the route UI transport as a public API. |
| P1 | Descriptor IDs such as perspective, projection, dashboard, relation, and source IDs are often locally unique but some demo payloads transport them without a plug-in-instance/schema qualifier. | Core qualifies IDs at persistence and assembly boundaries while preserving the plug-in-local ID. | **Partially migrated.** Status perspectives now have a typed qualified reference. Apply the same reference pattern to other descriptors before multiple coexisting plug-ins can share local names safely. |
| P1 | Documentation formerly assigned archive parsing and clock alignment rules to plug-ins. | Core owns safe archive decoding, transform fitting, uncertainty propagation, and selector resolution; node plug-ins provide locators, raw clock domains/anchors, and device-specific anchor meaning. | **Documentation migrated.** Add worker conformance tests so executable behavior cannot drift back. |
| P2 | Multi-node route/topology and temporal-topology adapters mix reusable-looking algorithms with synthetic scenario factories. | Typed, protocol-neutral algorithms belong in core; demo semantics and generated records belong in demo plug-in/federation packages. | **Structurally migrated.** The example policy and fixture construction now live in the explicit `demo/rsl_demo_plugin/` and `demo/rsl_demo_generator/` packages rather than blessing demo dictionaries as core contracts. Protocol-neutral helpers remain in `src/router_dump_analyzer/`; package-boundary tests reject reverse imports from core. Further extraction requires typed public inputs and outputs first. |
| P2 | Foundational schema descriptors originally accepted duplicate resource-kind, relationship, and causal-link IDs and did little field validation. | Core validates every static schema before any plug-in output is accepted. | **Migrated for the discovered gaps.** Descriptor IDs/labels/booleans/field lists are now validated, property/key/tag duplicates are rejected, and `PluginSchema` rejects duplicate kind/relation/causal IDs. Further cross-reference checks should grow with each new descriptor family. |
| P2 | Unbounded source-record query results still depend on plug-in redaction being correct before retention; only timeline marks are now forcibly projected. | Plug-in declares sensitivity/redaction; core enforces an allowlisted public projection and a separately authorized source-detail endpoint. | **Pending defense in depth.** Add declared searchable/display fields, a redacted-list projection, and explicit privileged raw-context retrieval rather than returning one shared record shape everywhere. |
| P2 | Plug-in descriptors can still carry literal colors, while the design says the web theme owns accessible rendering. | Plug-in provides semantic presentation tokens; core/browser theme maps tokens to accessible colors. | **Pending cleanup.** Keep validated colors only as a compatibility input, then migrate descriptors to bounded theme roles. |

## Components that are correctly placed

| Component | Owner | Reason |
|---|---|---|
| Typed canonical key encoding, opaque external IDs, incarnations, and reference validation in `plugin_api.py` and core storage | Core | These are format, identity, and integrity mechanics; the plug-in supplies key parts but not hashing or database identity. |
| State/relationship intervals, provenance, quality, evidence, unknown fields, selection ranges, and query budgets | Core | Their semantics must remain consistent across every plug-in and API consumer. |
| Resource kinds, relation types, presentation labels/icons, table fields, dashboards, normalized outcomes/conditions, and route-resolution text | Node/device plug-in | Their meanings change with platform, release, layer, and protocol. |
| Local forwarding and topology projections | Node/device plug-in | The plug-in interprets proprietary resources; the core validates the declared IR and traverses it generically. |
| Cross-member claim matching and ambiguity/corroboration policy | Federation/linker plug-in | This is semantic inference across independently reconstructed node worlds. |
| Exact-token grouping for a contract that explicitly declares exact equality, plus orchestration, limits, storage, and rendering | Core | The operation is generic only because the federation contract removes all domain interpretation. |

## Required migration invariants

- Core code must not branch on plug-in resource-kind, relation, source-type, or
  source-group IDs.
- Core code must not split or parse a `resource_id` to recover semantic fields.
- Missing plug-in normalization remains `unknown`; it is never inferred from
  display text.
- A source type references a declared opaque source group. `ctf` and `external`
  remain demo IDs, not core enums.
- A node plug-in may emit clock anchors but cannot align nodes. A
  federation/linker consumes the core-resolved per-member basis and cannot
  rewrite it.
- Plug-ins may select artifacts from the safe inventory, but only the core
  detects/opens archive layers and materializes validated inputs.
- Generic browser behavior is driven by validated descriptors. Plug-ins never
  provide HTML, CSS, JavaScript, SQL, URLs, callbacks, or layout coordinates.

This document records the boundary at audit time. Change a row to **Migrated**
only after implementation and tests prove that a second plug-in vocabulary can
use the same core path without a special case.
