# Plug-in author quickstart

Use this guide to build the smallest correct node/device plug-in without
reverse-engineering the server. Copy the working example first; add advanced
capabilities only after its validator and golden test pass.

The complete normative rules remain in `docs/plugin-contract.md`.

## What this guide produces

The example plug-in:

1. is an independently installable Python package;
2. is discoverable through `router_dump_analyzer.plugins`;
3. recognizes one platform from a safe artifact inventory;
4. selects one status file with explicit parser dispatch;
5. converts each line into a typed resource observation and a retained source
   record with evidence;
6. supplies a safe, optional plain-text copy projection for that source
   record; and
7. passes the generic author validator and its own golden test.

This repository is still a design/conformance demo. The validator proves the
plug-in-facing package and protocol shape. The core owns the only web command
and can load one installed or directly named plug-in at a time; it is not yet a
production upload and multi-plug-in selection coordinator. The demo publishes
the same example through normal entry-point discovery and contains no
application entry point.

## 1. Run the known-good example

From the repository root, using Python 3.12 in the analyzer environment:

```text
python -m pip install -e .
python -m pip install -e demo
router-dump-plugin-validate --list
python -X utf8 -m rsl_demo_generator --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
router-dump-plugin-validate demo_router --artifact demo/fixtures/minimal-status.jsonl --node-hint router-1 --metadata platform=demo-router-os --metadata software_version=1
python -m unittest discover -s demo/tests -v
```

The first command installs `router-dump-analyzer-core`. The second installs the
single demo distribution so its `demo_router` entry point is discoverable. Your
own device plug-in depends only on the core distribution; it does not depend on
the demo distribution.

The validator must end with:

```text
OK: demo.example-router
```

The generator verification proves that the tiny JSONL vector exactly matches
the plug-in-owned `CONFORMANCE_STATUS_RECORDS`; it is not a second hand-written
mock dump. Do not start a new implementation until these commands work
unchanged.

The browser bootstrap is core-owned. A node plug-in supplies normalized
identity, descriptors, counts, time bounds, and capabilities; it does not
build the `/v1/workspace` envelope or ship page templates.

The executable v1 `TopologyProjectionDescriptor` declares topology semantics
and supported status perspectives, but it does not contain browser-profile
fields. Today the coordinator or assembly profile adapter publishes
`presentation_roles` and optional safe `empty_action_label` text around a
selected plug-in projection. Use the exact `vpn` role only for a profile
genuinely intended for the VPN view; the browser will not guess from EVPN,
VRF, protocol, or projection names. Adding those fields directly to a device
plug-in requires a versioned protocol addition, not an extra attribute or
executable frontend code.

To run the generated example through the core-owned server after an assembly
has been generated, use either discovery mode:

```text
python -m pip install -e ".[web]"
router-dump-analyzer --plugin demo_router --input demo/fixtures/router-state-lab-demo.tgz --no-browser
python -m router_dump_analyzer --plugin-module rsl_demo_plugin --input demo/fixtures/router-state-lab-demo.tgz --no-browser
```

`--plugin` selects an installed entry-point name.
`--plugin-module PACKAGE[:ATTRIBUTE]` imports a module-level instance directly;
`ATTRIBUTE` defaults to `plugin`. The repository launch scripts generate the
large assembly when it is absent.

## 2. Copy the teaching slice, not the fixture runtime

The runnable teaching slice is kept beside the real demo so there is only one
example implementation:
`demo/rsl_demo_plugin/__init__.py`.

```text
demo/
|-- pyproject.toml
|-- fixtures/
|   `-- minimal-status.jsonl
|-- rsl_demo_plugin/
|   `-- __init__.py
|-- rsl_demo_generator/
|   `-- __init__.py
`-- tests/
    `-- test_plugin.py
```

Copy the parser/schema portion of `rsl_demo_plugin/__init__.py`, its
`CONFORMANCE_STATUS_RECORDS` plus renderer, its golden test, and the entry-point
declaration into a new independently installable `src/`-layout distribution.
Rename the distribution, import package, entry-point name, plug-in ID, platform
ID, parser ID, resource kinds, and fixture vocabulary. Do not copy the demo
runtime adapter, scenario builders, `ExampleRouterGeneratedProjectionPolicy`,
generated-corpus policies, or fixture generator.

`ExampleRouterPlugin.generated_projection_policy` is a demo-only offline
fixture facade. The comprehensive generator, archive validator, and runtime
loader all validate that one installed policy, and stored projection manifests
truthfully record `parser_replayed: false`. It is not a standard
`AnalyzerPlugin` hook and a normal device parser does not need it.

Copy none of the offline materializer into a normal live parser. If you are
deliberately building an independently versioned precomputed-projection
workflow, treat it as a separate application contract with equivalent
validation; the bundled implementation's current format and evidence rules live
in the [demo guide](../demo/README.md#generated-mock-dumps).

The entry point must target a module-level instance:

```toml
[project.entry-points."router_dump_analyzer.plugins"]
my_router = "my_router_plugin:plugin"
```

```python
plugin: AnalyzerPlugin = MyRouterPlugin()
```

Do not target `MyRouterPlugin` or a factory function. Do not load Python code
from a router dump.

## 3. Implement only five things

Subclass `AnalyzerPluginBase`. A first status-only plug-in implements these
members:

### A. Manifest

```python
manifest = PluginManifest(
    plugin_id="example.my-router",
    plugin_version="0.1.0",
    core_api_version=CORE_PLUGIN_API_VERSION,
    supported_platforms=("my-router-os",),
    supported_software_versions=">=1,<2",
    capabilities=frozenset({PluginCapability.STATUS_PARSE}),
    reconstruction_default=ReconstructionSupport.EXACT,
)
```

Use the standard `PluginCapability` enum. A capability is a promise that its
hook is implemented. `AnalyzerPluginBase` raises instead of silently ignoring
a declared-but-missing hook.

The normal v1 parsing API has no arbitrary runtime-configuration injection
hook. Keep parser defaults immutable and packaged with the plug-in; do not read
hidden environment variables. The optional `plugin.runtime.open(input_path)`
host adapter described below receives only the selected input path. The core
records `supported_software_versions`, while `probe()` owns the actual version
interpretation and `exact`/`compatible` decision.

### B. Static schema

`describe()` returns one deterministic `PluginSchema`. It declares every
resource kind, relationship type, source-record type, dashboard, topology
projection, and other semantic type that the plug-in may emit.

For a first plug-in, declare one resource kind and no relationships. The example
declares `INTERFACE`, its typed key field, safe properties, display fields, and
normalized condition field. It also declares one source-record group and one
`SourceRecordTypeDescriptor(source_type="status-json")`; every emitted source
type must appear in this static schema.

Every browser-visible state/key field must have a `PropertyDescriptor`.
Undeclared fields are server-side only and are removed from resource
projections and search text. Set `client_visible=False` for a declared property
that reducers or server-side analysis need but the browser must not receive;
set `sensitive=True` for secret material. Either setting also prevents that
property from becoming a search oracle or a public `condition_field` value.
`client_visible` defaults to `True` for compatibility, so the declaration
itself is the allowlist.

Never return HTML, JavaScript, CSS, SQL, remote URLs, or layout coordinates.
The core owns the generic browser pages, widgets, interaction logic, and
accessible rendering. Plug-ins contribute declarative domain presentation
only: labels, icons, tags, table/dashboard descriptors, topology projections,
and route or packet explanation text.

### C. Probe

`probe(inventory)` examines only `DumpInventory` metadata and safe
`ArtifactInfo` records. It returns:

- `ProbeReport(result=None)` when no recognizable artifact or signature is
  present;
- a `ProbeResult` with `ProbeMatchKind.NONE` when the artifact is recognizable
  but explicit platform or software-version evidence is incompatible; or
- a `ProbeResult` with confidence, reasons, detected values, and
  `ProbeMatchKind.EXACT` or `COMPATIBLE`.

An empty inventory is normal input and must not raise.

Do not open artifacts, archives, or host paths during probing.

### D. Input selection

`locate_inputs(inventory)` yields `InputSpec` or `PluginDiagnostic`.
Every new input sets `parser_kind`:

| Parser kind | Core calls | Required capability |
|---|---|---|
| `InputParserKind.STATUS` | `parse_status(reader, spec)` | `STATUS_PARSE` |
| `InputParserKind.CTF` | `parse_ctf(spec, messages)` | `CTF_PARSE` |
| `InputParserKind.TEXT_TRACE` | `parse_text_trace(reader, spec)` | `TEXT_TRACE_PARSE` |

`role` and `parser_id` are stable plug-in-owned identifiers. They do not select
the hook. `parser_kind=None` is accepted only for legacy adapters and fails the
default validator.

An input can contain several `artifact_ids`. Use that for a logical CTF tree;
the core performs safe materialization.

### E. Parser

`parse_status()` receives a quota-enforced `ArtifactReader`. Stream the file and
yield typed outputs. Do not read an unbounded file into memory.

The example yields two records for each accepted line. The first is a
`SourceRecordEmission` that preserves the decoded input and evidence; the
second is the typed `SnapshotObservation` that changes resource state.

The state observation contains:

- `resource`: canonical `ResourceKey`;
- capture interval for this particular record;
- `PropertyPatch` with exact set/remove/unknown semantics;
- plug-in-normalized `condition` and `ConditionClass`;
- `Provenance`, `Quality`, and `Evidence`.

The source emission uses a short bounded `message` for generic hover surfaces
and may use `copy_text` for an already-safe verbatim export. Malformed input
yields a stable, namespaced `PluginDiagnostic`; it must not crash the entire
parser.

## 4. Know which hooks are optional

These three hooks are always required:

| Hook | Purpose |
|---|---|
| `describe()` | Declare the immutable semantic schema. |
| `probe()` | Decide whether this platform/release matches. |
| `locate_inputs()` | Select bounded logical inputs and parser dispatch. |

Everything else is capability-gated:

| Capability | Override | Main output |
|---|---|---|
| `STATUS_PARSE` | `parse_status()` | observations, source records, diagnostics |
| `CTF_PARSE` | `parse_ctf()` | domain events, source records, diagnostics |
| `TEXT_TRACE_PARSE` | `parse_text_trace()` | domain events, source records, diagnostics |
| `EVENT_REDUCTION` | `apply()` | atomic `ChangeSet` |
| `EVENT_REVERSION` | `revert()` | inverse/unknown `ChangeSet` |
| `CORRELATION` | `correlate()` | causal links, relationship changes, clock anchors |
| `CONSISTENCY_CHECK` | `check_consistency()` | PASS/FAIL/UNKNOWN findings |
| `TOPOLOGY_PROJECTION` | `project_topology()` | bounded typed topology records |
| `FORWARDING_PROJECTION` | `project_forwarding()` | bounded forwarding IR mutations |
| `FORWARDING_TRACE` | `resolve_forwarding_step()` | one bounded node-local packet transition |

Inherit undeclared hooks from `AnalyzerPluginBase`; they return safe empty
results. Do not copy placeholder implementations into a new plug-in.

The generic node browser can show a bounded list of plug-in-projected route
choices, but v1 has no separate route-catalog hook. The coordinator derives
that capability from `FORWARDING_PROJECTION` or another explicitly versioned
projection. If your projection participates, give each route decision one
opaque, revision-stable `route_id`; keep node/revision/provider identity
explicit; and declare only basis kinds the coordinator can execute. Do not put
a URL in the plug-in or expect the browser to infer a destination, VRF,
label/SID, or fallback route from display text. Unknown IDs and unsupported
bases must fail closed. The normalized HTTP shape is in
[`api-contract.md`](api-contract.md#51-advertised-single-node-route-choices).

A projected row that only inventories local or null-scenario forwarding state
may set `traceable: false`, leave `trace_query` empty, and supply a bounded
`trace_unavailable_reason`. Core can still list that row, but it must not invent
a cross-node candidate or let the browser submit it as a trace.

### Optional host runtime for the core web command

Stop here for an ordinary parse-only plug-in. It does **not** need a
`plugin.runtime` attribute, and `router-dump-plugin-validate` can validate it
without one.

Add a runtime only when the core web command must open a plug-in-owned dump,
assembly, or precomputed projection directly. The loaded plug-in instance then
exposes `runtime` implementing `PluginRuntimeCapability`:

```python
from contextlib import contextmanager
from pathlib import Path

from router_dump_analyzer.runtime import PLUGIN_RUNTIME_CAPABILITY_ID


class MyRuntimeCapability:
    capability_id = PLUGIN_RUNTIME_CAPABILITY_ID

    @contextmanager
    def open(self, input_path: Path):
        session = open_my_non_web_session(input_path)
        try:
            yield session
        finally:
            session.close()
```

This is only the capability wrapper; `open_my_non_web_session()` represents
the plug-in's tested session constructor. The complete executable reference is
[`demo/rsl_demo_plugin/session.py`](../demo/rsl_demo_plugin/session.py),
covered by
[`demo/tests/test_runtime.py`](../demo/tests/test_runtime.py).

The yielded `PluginRuntimeSession` is a structural protocol with six non-web
surfaces:

| Session member | Requirement | Responsibility |
|---|---|---|
| `revision_store` | required | Immutable assembly/revision lookup implementing core `RevisionStore`. |
| `data_source` | required | Revision-scoped normalized dataset loading and optional indexed history implementing `NormalizedDatasetSource`. |
| `data_policy` | required | Opaque analysis/workspace metadata, route-row lookup, and safe source-record formatting implementing `NormalizedDataPolicy`. |
| `temporal_provider` | optional; use `None` when unsupported | Supply temporal descriptors; `for_revision()` must return the core `TemporalTopologyService`. |
| `topology_provider` | optional; use `None` when unsupported | Expose a stable `topology_id` and return the topology service from `get()`. |
| `route_provider` | optional; use `None` when unsupported | Return the route/packet service from `get()`. |

`NormalizedDatasetSource`, `NormalizedDataPolicy`, and
`NormalizedDataService` are exported by `router_dump_analyzer.normalized_data`.
The remaining structural protocols are exported by
`router_dump_analyzer.runtime`. Core constructs the data service and validates
that optional providers return the corresponding core service class; a plug-in
must not copy or replace those generic query engines.

Keep the two required adapters small:

```python
class MyDatasetSource:
    def revision_scope(self, revision_id): ...
    def load_dataset(self, revision_id=None, **selection): ...
    def revision_id(self, dataset): ...
    def indexed_history(self, dataset):
        return None  # or a structural IndexedHistory


class MyDataPolicy:
    def analysis_metadata(self, dataset): ...
    def workspace_metadata(
        self, dataset, *, revision_id, history_mode
    ): ...
    def route_resolution_capability(self, dataset):
        return {"available": False, "routes": []}
    def route_row(self, route_id, dataset):
        raise KeyError(route_id)
    def source_record_for_event(self, event): ...
```

`load_dataset()` returns the normalized envelope produced by the plug-in.
`indexed_history()` may return `None`; it is an optimization, not a second
semantic model. The two route methods above are the correct no-route
implementation. Core owns all resource/event traversal after these callbacks.
`open()` must be a context manager so the core application lifespan can close
stores, indexes, and caches exactly once.

This adapter supplies data and device policy, not an application. Do not return
FastAPI, `APIRouter`, middleware, routes, page templates, assets, or browser
code. The core creates all of those. Selecting a plug-in without this adapter
with `router-dump-analyzer` fails clearly, even though its ordinary parsing
contract may still validate successfully.

## 5. Use keys that cannot alias

The plug-in owns key meaning and ordering. The core owns canonical encoding and
identity.

Use native typed values when their meaning is already unambiguous:

```python
ResourceKey(
    namespace="vendor.router",
    node="node-a",
    layer="forwarding",
    kind="ETE",
    parts=(("etg_id", 41), ("path_id", 2)),
)
```

Use `KeyAtom` when the same representation can mean different things:

```python
KeyAtom("opaque_uint", 41)        # hardware ID, not IPv4
KeyAtom("ipv4", 0xC0000201)       # 192.0.2.1 encoded numerically
KeyAtom("uuid", uuid_bytes)       # exactly 16 bytes
KeyAtom("ipv6", ipv6_bytes)       # exactly 16 bytes
KeyAtom("bytes", opaque_bytes)
```

A native `UUID`, UUID text, UUID bytes, IPv6 bytes, an integer, and a string stay
distinct. Compound child keys are encouraged when identity is scoped by a
parent, such as `(etg_id, path_id)` for an ETE.

`ResourceKey.parts` must be a non-empty tuple of at most 32 unique
`(name, value)` pairs. Names are bounded dotted field paths. Values may contain
only `int`, `str`, `bytes`, `UUID`, `KeyAtom`, or nested tuples of those types;
tuple nesting, item counts, integer bit length, and text/byte length are
bounded by the core. Floats, mappings, lists, booleans, and arbitrary Python
objects are rejected before storage or federation.

Never:

- join key parts into an ambiguous display string;
- use a boolean key part;
- parse another resource's display ID to recover semantics; or
- use a plug-in run ID as resource identity.

Relationships, not key parsing, control grouping and dependency traversal.
Analysis `revision_id` values are separately core-owned opaque identifiers.
They may contain `/`; neither plug-ins nor clients may split them to recover
node, platform, or resource meaning. A client putting one in a URL must
percent-encode the whole value and use the revision-scoped route returned by
the API.

## 6. Preserve source records and evidence

Every output should point back to stable evidence such as `line:12`,
`bytes:100+20`, `ctf:stream=2,message=481`, or a JSON pointer.

Parser hooks may yield `SourceRecordEmission` for matched or unmatched input.
The plug-in supplies decoded source semantics and an optional
`matched_event_uid`. Use `matched_event_uids` when one decoded input contributes
to several normalized events. It does **not** assign `source_record_uid`; the
core turns the emission into a persisted `SourceRecord` with stable identity.

Set `copy_text` only when the plug-in can provide a safe canonical plain-text
form for an operator to copy. The plug-in must redact secrets before assigning
it: core treats the string as opaque and will return it verbatim. This is not
the short hover `message`, raw private payload, HTML, a template, or a browser
callback. It must be a string, contain no NUL, and be at most 65,536 UTF-8
bytes. The core keeps it out of ordinary log/timeline/bootstrap projections,
resolves explicit immutable selections, and applies deduplication plus
item/byte quotas. The host authorizes access to that endpoint; the browser owns
selection gestures and the final Clipboard API call.

A source-record group may set a 1-to-80-character `copy_action_label`, such as
`Copy status rows`. A mixed-group selection uses a generic core label rather
than choosing one plug-in label arbitrarily.

`RecordLanePreset.pattern` uses the same deterministic subset as a user-created
record lane: top-level alternatives composed of literals, character classes,
dot, anchors, and at most one `*`, `+`, or `?` quantified atom per alternative.
Groups, counted repetition, lookaround, backreferences, ambiguous/nested
repetition, and unsupported escapes are rejected. Prefer simple patterns such
as `ESI|mass withdraw`, `^BGP`, or `error.*peer`; the core applies the same
pattern, haystack, lane, and result bounds at runtime.

For trace normalization:

1. derive `DomainEvent.event_uid` with
   `derive_event_uid(plugin_id, parser_id, source_ref, local_discriminator)`;
2. emit a `SourceRecordEmission` for retained input when requested;
3. set its `matched_event_uid` or `matched_event_uids` when normalization
   succeeded; and
4. keep unmatched records rather than inventing domain events.

The helper uses a versioned, length-delimited SHA-256 encoding of the canonical
source identity. Use `local_discriminator` only when one source record produces
several domain events. Its type is significant, so integer `1`, string `"1"`,
and byte `b"1"` remain distinct. Never use Python `hash()`, random UUIDs, the
wall clock, or list position after filtering. Increment `parser_id` when a
release changes how one source record is split into domain events.

### Represent topology resource lifecycles

If your topology adapter emits the compact resource replay shape, start with
`initial_status` and `initial_state`, then place updates in `changes[]` with a
`time_ns`. Use `status: "down"` when the resource still exists but is unusable.
Use boolean `exists: false` for deletion and `exists: true` for recreation. You
may instead use the generic `operation` values `delete`/`remove` and
`create`/`add`; explicit `exists` wins when both are present.

Set `state_changed: false` on a failed or proposed update that changed nothing.
The core then ignores that change's lifecycle, status, and state fields.
`valid_from_ns` is inclusive and `valid_to_ns` is exclusive and always bounds
the result, so a create cannot extend a resource outside its declared validity
window. A delete followed by a create produces an absence gap for the same
canonical resource ID.

## 7. Keep core and plug-in responsibilities separate

Put a decision in the node/device plug-in when it depends on:

- platform, release, layer, or protocol vocabulary;
- resource kind or key-field names;
- UUID/byte/integer interpretation;
- vendor status normalization;
- resource relationships or matching rules;
- candidate paths, directional/per-visit forwarding decisions, or which exact
  connectivity-domain key and attachment resources a next hop names;
- route-resolution text;
- endpoint attachment or local delivery/termination meaning;
- topology projection;
- dashboards, table columns, labels, or icons.

Put mechanics in core when they apply identically to every plug-in:

- safe archive inventory and materialization;
- canonical envelopes and key serialization;
- clock fitting and temporal selector resolution;
- interval persistence and pagination;
- exact equality joins between a plug-in-declared connectivity-domain
  matcher/key and the selected normalized domain plus current attachments,
  including fail-closed missing/ambiguous/truncated/unusable results;
- immutable flow direction, exact endpoint-goal matching, and bidirectional
  reachability aggregation;
- budgets, validation, authorization, and generic rendering.

Cross-node matching that interprets normalized claims belongs to a separate
federation/linker plug-in. A node plug-in stops at its local connector claim.

### Route endpoints and trace starts

This is optional advanced forwarding behavior; the minimal example does not
implement it. Keep these identities separate:

- the packet's immutable source and destination endpoints;
- the forward trace start/ingress where observation begins; and
- the target endpoint for the current direction.

A start may be a transit router. Do not rewrite the packet source to that router
and do not require return traffic to revisit it. The default reverse traversal
starts from a declared destination attachment and targets the exact source
endpoint. Core swaps those directional goals and aggregates the result.
If a bidirectional request explicitly chooses a reverse start, it must be one
of those destination attachments; an arbitrary return-side observation proves
only the suffix it actually traverses.

Your node plug-in declares normalized, time-valid endpoint attachments and
classifies local delivery or origination using canonical resources or typed
match references with provenance and evidence. It does not assemble a
multi-node route. The federation/linker plug-in matches bounded attachment and
boundary claims between members. Core exact-matches the declared terminal,
retains attachment uncertainty and multipath coverage, and reports whether
forward reached the destination and return reached the source. Its
`evaluate_endpoint_reachability_pair()` helper classifies the pair after those
typed directional endpoint results are known; it does not replace plug-in
terminal evidence.
All plug-in-selected active branches must reach before core reports a fully
reachable direction. Mixed success/failure is
`partial_active_reachability`, while incomplete evidence remains unknown.

Node-sequence symmetry is only explanatory. A forward trace starting inside the
flow and a full return trace have `path_relation=not_comparable`; that does not
make a bidirectionally reachable flow inconsistent. Conversely, a complete
return path that ends at the forward start but not the source endpoint is not
successful. The executable endpoint-pair cases are in
`tests/test_multi_node_route.py`.

### Packet transformations and trace-time forwarding

This is an optional advanced capability. Keep it separate from status parsing
and follow this order:

1. Implement and test `FORWARDING_PROJECTION` first so the plug-in exposes
   stable canonical forwarding objects at a qualified perspective.
2. Declare `FORWARDING_TRACE` only when
   `resolve_forwarding_step(request, world)` returns a bounded,
   node-local `ForwardingStepResult`. Do not return an end-to-end route or read
   another assembly member.
3. Represent the current packet with `ForwardingPacketState`. Put
   `ForwardingPacketLayer` values outermost to innermost, give each layer a
   stable identity within the branch, and use your own versioned contract ID
   and typed fields. Core does not know what a label, SID, VNI, VPN, or
   proprietary wrapper means. The layer `label` is presentation-only and is
   excluded from equality, hashing, continuity, and structural change
   detection.
4. Return one `ForwardingPacketTransition` whose `before` matches the request
   and whose `after` is the actual plug-in-declared result. Choose the
   normalized disposition (`continue`, `deliver`, `drop`, `punt`, `replicate`,
   or `unknown`) from device semantics and attach explanation/evidence. A
   `continue` result is non-terminal and names its next forwarding object. Any
   other disposition is terminal for that linear branch and supplies no next
   object or lookup context.
5. If size matters, declare both `ForwardingSizeObservation` and
   `ForwardingMtuConstraint` using the same opaque `basis_contract_id`. Core
   performs comparison only; your plug-in owns overhead, effective MTU,
   fragmentation, PTB/ICMP behavior, and the final disposition.
6. Have the coordinator call `validate_forwarding_step_result()` before
   accepting the result. It checks the request step and packet-before state and
   retains exact user steering rule/candidate coupling without interpreting
   the candidate.
7. Test complete continuity, incomplete packet size or policy-scope evidence,
   exact cycle identity, and the independent step/hop/recursion budgets with
   the helpers in `route_trace_core.py`.

Do not encode push, swap, PHP, SR behavior, or decapsulation only in
`action_label` or `resolution_text`; the before/after packet states are the
machine-readable result. A removed outer layer with an inner layer retained is
valid and lets core represent nested tunnels without protocol inference.
Adding or removing that outer layer does not by itself mark every retained
inner layer as moved; `moved` means relative order among retained layers
changed. The structural diff's `complete` flag is false when either packet
identity is incomplete, so an empty diff is not overstated as conclusive.

`ForwardingSteeringRule` is user-supplied counterfactual input. Core
exact-matches its target step and optional expected packet snapshot, resolves
one highest-priority rule, and preserves actor/rule provenance. A forced
transition must be `origin=user_forced` and must never replace observed
reachability. Normal device policy remains `origin=node_plugin`.

The public types and core helpers are executable and covered by
`tests/test_packet_trace_core.py`. The generated demo evaluates its declared
packet cases through those generic helpers; current case counts and fixture
details live in the [demo guide](../demo/README.md#generated-mock-dumps).
This is not yet a production coordinator that discovers and calls
`resolve_forwarding_step()` for every installed node. See
[Packet state, transitions, and MTU](plugin-contract.md#packet-state-transitions-and-mtu)
for the normative rules.

### Forwarding loops and ingress-dependent policy

This is an optional advanced forwarding capability; the minimal example does
not need it. When your device suppresses a candidate according to where the
packet or route entered, do not hide that rule in a display string or an opaque
attribute:

1. Put the proprietary equality identity in `ForwardingPolicyScope`. Its
   `contract_id` and ordered typed arguments belong to your plug-in.
2. Attach a `ForwardingCandidateConstraint` to the affected
   `ForwardingMember`, including the applicable traffic classes and
   `ResolutionContribution` evidence.
3. Tell core whether the ingress-scope set is complete. A known-empty set is
   different from an incomplete capture: an applicable non-match is permitted
   only when `ingress_scopes_complete=True`; otherwise it is unknown.
4. Let core's `evaluate_forwarding_constraint()` produce one
   `ForwardingPolicyDecision`, or use `evaluate_forwarding_policy()` to produce
   a `ForwardingPolicyEvaluation` containing the aggregate verdict and all
   decisions. Core compares complete scopes only; it does not understand EVPN,
   BGP, ESI, EVI, DF, VLAN, or vendor policy.
5. Canonicalize all state needed to distinguish a forwarding visit in
   `ForwardingTraversalStateKey`. Include the forwarding object/domain,
   ingress resource, lookup and packet context, policy scopes,
   `policy_scopes_complete`, member, and perspective. Do not use only a router
   ID.
6. Use `detect_forwarding_cycle()` when you need a
   `ForwardingCycleReport | None`. Use bounded
   `evaluate_forwarding_traversal()` when you need a
   `ForwardingTraversalEvaluation`; its optional `.cycle` carries that report.
   A same-router revisit with changed context is not automatically a loop.

Keep a policy-blocked candidate in output with its explanation. It is an
intentional exclusion, not a failed physical link. Test at least an exact
scope match, a known non-match, an incomplete-scope non-match, a
non-applicable class, an unknown class, an exact recursive or cross-node
cycle, a legitimate changed-state revisit, a separate hop-limit result, a
transit start distinct from the traffic source, and a return path that reaches
the source without revisiting that start.
The executable type cases are in `tests/test_plugin_api.py`; the core helper and
end-to-end route cases are in `tests/test_multi_node_route.py`. The complete
ownership and conformance rules are in the forwarding section of
`docs/plugin-contract.md`.

## 8. Validate after every change

Run:

```text
router-dump-plugin-validate my_router --artifact path/to/representative-status.txt --node-hint router-1 --metadata platform=my-router-os --metadata software_version=1
python -m unittest discover -s path/to/my_plugin/tests -v
```

The generic validator checks:

- entry-point target is an instance;
- manifest API version and required fields;
- deterministic `PluginSchema`;
- required hooks;
- capability-to-hook overrides;
- empty-inventory probe and discovery behavior;
- representative author-fixture probe and input selection when `--artifact`
  and metadata are supplied;
- bounded discovery output; and
- explicit parser dispatch with a matching capability.

It does not open the fixture or execute a parser, so it cannot verify
proprietary semantics. Your golden tests must cover normal, missing, malformed,
truncated, repeated, out-of-order, failed-update, and clock-skewed input wherever
each case applies to the declared capabilities. Record non-applicable cases in
the test plan rather than fabricating meaningless tests. Scale parsers must also
stream 100K+ records within their budget.

The validator also does not require the optional web-runtime adapter. If your
plug-in exposes `plugin.runtime`, add a separate smoke test that enters
`runtime.open(input_path)`, calls `validate_runtime_session()`, exercises every
non-`None` provider, and proves the context closes its resources. Then run the
core command against that input.

Common failures:

| Message | Fix |
|---|---|
| `entry-point target must be ... instance` | Export `plugin = MyPlugin()`. |
| `core_api_version ... does not match` | Build against the installed core API. |
| `requires an override` | Implement the advertised hook or remove the capability. |
| `has no parser_kind` | Set `InputParserKind` on every new `InputSpec`. |
| `does not declare ...` | Add the matching standard capability. |
| `describe() must be deterministic` | Build one immutable schema without clocks, randomness, or input state. |
| `does not expose a 'runtime' capability` | Use the validator for a parse-only plug-in, or add the optional non-web runtime adapter before using the core web command. |

## Definition of done

A first plug-in is ready for review only when:

- [ ] installation and entry-point discovery work in a clean environment;
- [ ] the generic validator prints `OK`;
- [ ] empty and missing input return a report/diagnostic rather than raising;
- [ ] every selected input has explicit parser dispatch;
- [ ] every emitted type is declared in `PluginSchema`;
- [ ] keys are typed, stable, and collision-safe;
- [ ] status/outcome/effect are not inferred by core or browser code;
- [ ] observations and events carry evidence and honest quality;
- [ ] failed events do not mutate state unless device semantics prove a change;
- [ ] golden tests cover applicable bad-input and temporal edge cases; and
- [ ] no plug-in-specific branch was added to core or the browser.

If the plug-in also supplies an input session to the core web command:

- [ ] `plugin.runtime.capability_id` equals
  `router_dump_analyzer.runtime.v1`;
- [ ] `open(input_path)` yields a valid non-web session and closes it once;
- [ ] every unsupported optional provider is explicitly `None`; and
- [ ] both installed-name and direct-module loading are smoke-tested as
  applicable.

After this passes, use the relevant advanced sections of
`docs/plugin-contract.md` for reducers, temporal correlation, dashboards,
topology, forwarding, and federation.
