# Router State Lab example plug-in and fixture generator

This is the repository's one demo distribution. It has no application or
console entry point; it registers only a plug-in discovery entry point. It
contains:

- one installed `AnalyzerPlugin` entry point named `demo_router`;
- the example plug-in's parser, device/protocol policy, and non-web fixture
  input/session adapters;
- the canonical `router-state-lab-default.scenario.json` authoring save plus a
  standard-library adapter and deterministic scalable mock-dump materializer;
  and
- plug-in-owned conformance fixtures and tests.

The distribution uses the collision-resistant import packages
`rsl_demo_plugin` and `rsl_demo_generator`. It deliberately does not publish
generic top-level packages named `plugin` or `generator`, which are likely to
collide with unrelated dependencies in a shared Python environment.

The only `router-dump-analyzer` executable, FastAPI application, routes,
lifecycle, generic query services, and frontend belong to
`router-dump-analyzer-core`. The demo depends on the core base package without
its `web` extra. A deployment that serves the UI installs
`router-dump-analyzer-core[web]` separately; core never imports or installs the
demo.

## Install and run

From the repository root:

```powershell
.\scripts\setup_demo.cmd
.\scripts\launch_demo.cmd -NoBrowser
```

The setup script creates or updates the `router-dump-analyzer-demo` Conda
environment, installs the core and this demo as separate editable
distributions, and runs their Python suites.

Open `http://127.0.0.1:8765/` for the multi-node fabric or
`http://127.0.0.1:8765/node` for the individual-node temporal workspace. The
root page is canonical; `/topology` remains a compatibility alias. If port
8765 is occupied, use:

```powershell
.\scripts\launch_demo.cmd -Port 8876 -NoBrowser
```

The launcher first checks that the archive contains the canonical full-scale
node set, a checksum-matching generated dump pack for every node, and the
SHA-256 digest of `router-state-lab-default.scenario.json`, together with a
deterministic fingerprint of the generator and loaded demo plug-in code that
interpreted it. It generates a missing archive and atomically replaces only an
unsuitable, source-stale, or materializer-stale archive with the exact bounded
generator owner manifest. Unknown files, final symlinks, and non-regular
preferred paths remain untouched; the launcher uses the fixed
`router-state-lab-demo.generated.tgz` recovery sibling and passes that selected
path to the core. It also enables core-owned durable state at
`.runtime\control-plane` by default. Use `-ControlPlaneDir PATH` on Windows or
`--control-plane-dir PATH` on Linux/WSL to choose another location. Binding a
non-loopback host requires the corresponding explicit
`-TrustControlPlaneHeaders` or `--trust-control-plane-headers`
development-only override.

On the node page, expand **Durable review** above the normalized event log.
Enter explicit tenant, project, workspace, and reviewer IDs; the UI labels
this as trusted-header local development and stores those values only in the
browser. The active dump must already have been published into that explicit
workspace through the core ingestion pipeline: launching the browser server
does not add its startup input to the durable catalog. The UI resolves the
page's active runtime revision to exactly one catalog revision before
persisting markers. If durable state is absent, unauthorized, or cannot
resolve that revision unambiguously, existing browser-only markers continue
to work and no durable write is attempted. Selected event/source-record rows
can be marked or unmarked; two or more selected events can be saved as one
ordered manual correlation. A resolved read-only identity can inspect markers
and generate reports but cannot change annotations or correlations.
Correlation reports can target explicit revisions, a mutable session, or an
immutable session snapshot and can be copied or downloaded, while the page
itself continues to render only its active revision. Ambiguous durable writes
retain their bounded retry identity across reload. The panel separates
connected-scope discard from a warned all-scope reset; neither action changes
an outcome that may already exist on the server.

For a manual launch, activate the setup environment and ask
the generator for that selected path before loading the installed plug-in entry
point directly:

```powershell
conda activate router-dump-analyzer-demo
$demoArchive = python -X utf8 -m rsl_demo_generator `
  --ensure-launchable demo/fixtures/router-state-lab-demo.tgz --path-only
router-dump-analyzer --plugin demo_router `
  --input $demoArchive `
  --control-plane-dir .\.runtime\control-plane `
  --no-browser
```

The analysis application does not expose OpenAPI JSON, Swagger UI, or ReDoc
by default. Add `--expose-api-docs` only on a loopback listener when those
development endpoints are needed; a non-loopback bind is rejected.

In that activated environment, source-tree development can bypass installed
entry-point discovery without changing ownership:

```powershell
$demoArchive = python -X utf8 -m rsl_demo_generator `
  --ensure-launchable demo/fixtures/router-state-lab-demo.tgz --path-only
python -m router_dump_analyzer `
  --plugin-module rsl_demo_plugin `
  --input $demoArchive `
  --control-plane-dir .\.runtime\control-plane `
  --no-browser
```

To exercise the demo's ordinary parser through the durable core queue, use the
small conformance fixture rather than the precomputed runtime-v1 assembly:

```powershell
$env:PYTHONUTF8 = "1"
router-dump-ingest --plugin demo_router `
  --state-dir .\.runtime\demo-headless `
  --tenant demo-tenant `
  --project plugin-conformance `
  --workspace first-run `
  --input .\demo\fixtures\minimal-status.jsonl `
  --node-hint router-1 `
  --output .\artifacts\demo-ingestion.json `
  --pretty
```

This creates the project/workspace if absent, content-addresses the upload,
durably stages its fixture admission, probes the installed demo entry point,
parses through the standard runtime-v2 hooks, then durably stages and
publishes one immutable catalog revision. A replay after either lost catalog
response uses the same operation ID; publication replay does not parse again.
Probe and parsing run in fresh `spawn` child processes with the core's bounded
deadline (300 seconds by default, capped by the command's `--timeout`). The
demo plug-in and coordinator are module-level, importable, and spawn-picklable
for this reason. A timeout/crash is killed and reaped and cannot publish a
partial dataset; the child remains trusted host-user code rather than a
security sandbox.
The `.runtime\demo-headless` directory is disposable local state. Repeat
`--input` to exercise several independently versioned fixtures in one
workspace.

To serve that state without opening the demo analysis or frontend, run the
core-owned API-only server on loopback:

```powershell
router-dump-server --plugin demo_router `
  --state-dir .\.runtime\demo-headless `
  --trust-control-plane-headers `
  --port 8876
```

This trusted-header mode is development-only. A real deployment replaces it
with `--identity-resolver-module PACKAGE:ATTRIBUTE`, whose synchronous callable
verifies credentials and returns `ControlPlaneIdentity`. The plug-in selector
is an immutable allowlist; repeat `--plugin` for additional installed
candidates, or use repeatable `--plugin-module` during source development, but
never mix the two forms. This process has root health and control-plane APIs,
not the demo UI, analysis routes, or static assets. OpenAPI/Swagger/ReDoc are
disabled by default; `--expose-api-docs` is accepted only on loopback.

The demo does not implement that queue, catalog, tenant model,
multi-revision session, annotation store, correlation report, HTTP endpoint,
or headless command/server. All are core-owned and are documented in the
[durable control-plane guide](../docs/control-plane.md). The demo supplies only
recognition, parsing, normalized device semantics, and its fixture adapters.
If plug-in-owned labels or metadata later enter an AI-facing report, the core
recursively renders Unicode line/paragraph separators, NEL, every non-ASCII
space separator (including NBSP), ZWSP, BOM, bidi formatting controls, and
assigned blank Hangul fillers, Khmer inherent-vowel characters, the Braille
blank glyph, and Egyptian hieroglyph blanks as visible `\\uNNNN` text. ZWNJ,
ZWJ, and the Khitan small-script filler retain their shaping semantics.
Combining grapheme joiner, unregistered or misplaced variation selectors,
U+FFFC OBJECT REPLACEMENT CHARACTER, and private-use characters may remain in
bounded source labels, but the report makes those characters explicit while
preserving surrounding text. U+FE0E/U+FE0F remain raw only as an exact
Unicode-registered adjacent base-selector pair; repeated or standalone
selectors are escaped, while independent valid pairs across a ZWJ sequence
remain intact. Every selector remains invalid in catalog identifiers. Literal backslash
escape-looking text remains distinct from actual escaped Unicode in the core
report. The demo has no report formatter and must not encode device meaning
only through invisible or private-use text.

The launchers create missing or unsuitable generated fixtures before starting
the server. Their automatic bounded check hashes each opaque node pack but does
not decode it; explicit fixture validation remains available for the full
nested structural audit. An unknown recovery sibling is never replaced and
causes launch preparation to fail closed. See
[`samples/README.md`](../samples/README.md) for the corpus layout and
generator-owned scenario phases.

## Validate the example plug-in

The teaching implementation is
[`rsl_demo_plugin/__init__.py`](rsl_demo_plugin/__init__.py).
It recognizes `minimal-status.jsonl` and maps each accepted row to a typed
`INTERFACE` snapshot plus a retained source record.

Run the linear, copy-paste
[`plugin-author-quickstart.md`](../docs/plugin-author-quickstart.md#1-run-the-known-good-example)
workflow to verify the fixture, validate the installed entry point, and execute
the golden test. That guide is the canonical validation procedure and then
shows exactly which plug-in, fixture, test, and entry-point pieces to copy into
a new independently installable distribution. A production plug-in depends on
`router-dump-analyzer-core`, not on this demo package.

## What the example owns

Each non-empty line in `fixtures/minimal-status.jsonl` is one complete
interface observation:

```json
{"kind":"interface","captured_at_ns":1759680000000000000,"source_sequence":10,"lifecycle":"create","ifindex":7,"name":"xe-0/0/0","admin_status":"up","oper_status":"up","description":"core uplink"}
```

The plug-in owns that JSON vocabulary, the typed `ifindex` key, platform and
version matching, status normalization, resource descriptors, evidence,
bounded hover text, and safe source-record `copy_text`. The example assumes
that `ifindex` is stable within one analysis revision and maps `oper_status=up`
to healthy, `down` to error, and other accepted values to unknown.
The generic validator preserves useful safe diagnostics from this plug-in but
bounds or replaces unsafe exception/path/display text before it reaches a
terminal or CI log. The package fingerprint includes ordinary files and
contained aliases even if their basename resembles `.git` or `__pycache__`;
only actual metadata/cache directories are pruned.
At one timestamp, `source_sequence` establishes producer order before the
stable record identity tie-breaker. The checked fixture includes create,
modify, and window-only observations; shared temporal replay also treats
`insert` as a creation operation.

Core owns safe artifact access, validation, stable record identity, persistence,
temporal reconstruction, application composition, APIs, selection budgets, and
rendering. The generic
HTML, JavaScript, CSS, widgets, and interactions are shipped once under the
repository's core-owned `frontend/`. Plug-ins may contribute only validated
declarative domain presentation—labels, icon paths, tags, table/dashboard
descriptors, topology projections, and route or packet explanation text. They
do not ship executable frontend code.

The generated runtime examples keep exact topology keys and dashboard
comparison fields inside the core's documented bounds. Their conformance tests
also exercise typed exact matching and explicit endpoint-start evidence; copy
those patterns instead of flattening opaque keys or inferring route symmetry.
The topology adapter constructs `TopologyPluginSemanticsDescriptor` before it
emits a normalized domain claim. Arbitrary bounded roles remain plug-in-owned;
only `TopologyDomainRole.EXTERNAL` plus complete projection coverage authorizes
the generic core to classify a one-sided domain as external. Inter-node
presentation claims may use `InterNodeRouteTraceRole.INCLUDE` or
`InterNodeRouteTraceRole.OVERLAY`; `CONFLICT` is reserved for core aggregation
output and must not be emitted by a plug-in. This generated fixture uses shared
segment claims rather than pairwise connector claims; the inter-node role
boundary is exercised by the core conformance tests.
The runtime gives core raw topology values only at the plug-in hook; generated
projection JSON contains the core's already-normalized tagged form and is
validated directly on reload. Dashboard examples rely on presence-aware fields:
explicit null remains a value, missing stays missing, and numeric statistics do
not coerce strings or booleans.

## Core ingestion and generated-fixture compatibility

An ordinary live parser needs no `plugin.runtime`. Core-owned runtime v2
inventories a regular file, directory, tar, or ZIP; passes only logical
artifact IDs, read-only streams, and session-private materializations; calls
`describe()`, `probe()`, and `locate_inputs()`; capability-dispatches parsers;
and validates/normalizes their output. The plug-in never sees the original
host path.
The example probe deliberately uses one short reason and bounded detected
platform/version strings; the shared core contract requires finite confidence
from 0 through 1, 1 to 128 reasons (1,024 characters each), and detected text
no longer than 256 characters.

The comprehensive generated assembly is different: it is a deliberately
precomputed fixture whose stored projections are validated and loaded instead
of replayed by the small teaching parser. The example therefore exposes
`plugin.runtime` with
`capability_id = "router_dump_analyzer.runtime.v1"` as a compatibility adapter.
The full 125,000-event-per-node demo remains on this v1 path.

Its `open(input_path)` method is a context manager that yields one non-web
session. The session exposes six core-consumed surfaces:

1. `revision_store`, the immutable assembly and revision catalog;
2. `data_source`, revision-scoped normalized dataset loading plus an optional
   structural history index;
3. `data_policy`, example metadata/workspace, route-row, and source-record
   presentation callbacks;
4. `temporal_provider`, revision-scoped temporal policy;
5. `topology_provider`, the plug-in's topology projection policy; and
6. `route_provider`, the plug-in's route/packet policy.

The first three are required by the compatibility runtime; the last three may
be `None` when a plug-in does not support those views. The core enters and
closes the session, constructs `NormalizedDataService`, and owns
resource/state, relationship, table, dashboard, range, redaction, and
client-projection algorithms. A runtime provider must not return a FastAPI app,
`APIRouter`, middleware, templates, frontend code, or a substitute query
engine.

The demo assembly cache is likewise only an input adapter. It serializes cold
materialization without holding the cache-bookkeeping lock, so existing leases
and cache hits remain usable while another generation loads. Lease copies
preserve the caller's current shallow top-level view and keep the shared
generation alive; core still owns request/session lifecycle and query
semantics.

The current core-built runtime-v2 session for a standard parser exposes the
first three surfaces itself. Its optional temporal, topology, and route
providers are `None`, its source has no structural history index, and the
route catalog is unavailable. Those limitations are explicit; resource names
or properties do not activate a provider. Because this demo instance has a
runtime-v1 compatibility adapter for its large archive, core selects that
adapter for the demo CLI. `tests.test_ingestion` exercises the teaching parser
through the core v2 coordinator and workspace instead.

Runtime-v2 currently retains validated
`RelationshipCollectionObservation` markers as private ingestion metadata; it
does not yet apply their completeness inference to public relationship
intervals. Likewise, optional semantic hooks are executable and testable
through core's root-exported `PluginCapabilityExecutor`, but that caller does
not install the missing temporal, topology, or route providers.

## Generated mock dumps

The small JSONL file is a conformance vector, not the comprehensive mock dump.
It is rendered from the plug-in-owned `CONFORMANCE_STATUS_RECORDS`; verification
fails if the checked-in bytes drift. Full single-node and multi-node packets
are produced by the same deterministic generator. Use the canonical generation
and verification commands in the
[`samples/README.md`](../samples/README.md#generate); this section owns only the
demo-specific projection, evidence, and runtime-loading contract.

### Compact runtime-v2 conformance corpus

The generator also owns a small deterministic heterogeneous archive. Generate
and byte-verify it without touching the large demo:

```powershell
python -X utf8 -m rsl_demo_generator `
  --write-ingestion-conformance-corpus .\demo\fixtures\runtime-v2-ingestion-conformance.tgz
python -X utf8 -m rsl_demo_generator `
  --verify-ingestion-conformance-corpus .\demo\fixtures\runtime-v2-ingestion-conformance.tgz
python -m unittest tests.test_ingestion -v
python -m unittest discover -s state-dump-generator/tests `
  -p "test_runtime_v2_vectors.py" -v
```

The archive contains eight raw/metadata members: current status input, text
log, synthetic CTF container, malformed status and CTF, an unsupported file,
the semantic vector, and its manifest. The example plug-in currently selects
and parses only the status member through runtime-v2 ingestion. The remaining
members and the standalone
`state-dump-generator/tests/fixtures/runtime-v2-ingestion-temporal-conformance.json`
label their required execution stage. In particular, the core has no built-in
CTF decoder; CTF dispatch requires an explicitly supplied `TraceDecoder`.

The vector covers exact integer timestamps, equal-time `source_sequence`
ordering, create/modify and insert-as-create lifecycle semantics, a window-only
uncertain observation, native numeric/UUID/byte/compound keys, exact versus
rule-resolved relationships, retained status/text/CTF categories, and
malformed or unsupported artifacts. A label such as
`requires_plugin_projection` describes a conformance target, not functionality
silently supplied by core.
Normalized domain-event timestamps stay inside signed `int64`; their optional
uncertainty is non-negative and the complete uncertainty interval also stays
inside signed `int64`. The public event constructor and
the runtime-v2 host both enforce that narrower temporal contract.

### Canonical source pipeline

[`router-state-lab-default.scenario.json`](router-state-lab-default.scenario.json)
is the human-authored source for future generated demo dumps. It is an ordinary
`state-dump-generator-scenario/v1` save. Open and edit it with the independent
[State Dump Generator](../state-dump-generator/README.md); do not edit a
generated TGZ and expect the change to survive regeneration.

From the repository root, the complete PowerShell workflow is:

```powershell
python -m pip install -e .\state-dump-generator
python -m state_dump_generator validate .\demo\router-state-lab-default.scenario.json
python -m state_dump_generator serve --open
```

Click **Open** in the studio and select the canonical JSON to preview or edit
it. After saving, generate and verify the full demo assembly, then launch it:

```powershell
python -X utf8 -m rsl_demo_generator `
  --output .\demo\fixtures\router-state-lab-demo.tgz
python -X utf8 -m rsl_demo_generator `
  --check-launchable .\demo\fixtures\router-state-lab-demo.tgz
.\scripts\launch_demo.cmd -NoBrowser
```

The authoring tool and demo do not import one another. The demo's
standard-library adapter consumes the saved node definitions, generation
defaults, node-local attachment evidence, and explicit historical
observations. The materializer then adds distinct deterministic filler and
plug-in projections to reach the configured scale. The exact source-file
digest and materializer fingerprint are recorded in the outer manifest and
every node pack. Launch preflight rereads the save and recomputes the
fingerprint, so it rejects a TGZ generated from an older save or older
materialization code. Generation also rechecks both immediately before atomic
publication. Launch preparation regenerates the archive only when the
destination satisfies the generator's ownership rules.

The outer TGZ contains ten node packs. Each node has a 125,000-event and
7,500-resource scalable baseline plus its explicit authored observations and
final resources, including at least 100,000 real state-changing events, raw
CTF/status containers, one normalized history, and mock-provider
topology/route/forwarding/packet projections. Both browser workspaces select
those exact revisions through the core revision-store contract. The generated
projection manifest uses the installed example plug-in's
`generated_projection_policy`, whose stable provider identity is
`demo.example-router`. Generation, archive validation, and runtime loading all
validate the same policy ID, plug-in version, and projection format. The stored
projection is explicitly `precomputed_during_generation` with
`parser_replayed: false`; runtime validates and reads it rather than claiming
that the small status parser rebuilt the comprehensive corpus. This policy is
a demo-owned facade, not a generic core hook or a second plug-in.

The generated assembly, coverage registry, and precomputed projection currently
use format version 2. The projection capability is immutable and names every
member with its relative path, media type, serialization, and record
collection. The archive also records a
`precomputed_projection_capability` and `generated_schema_contract`; the
installed entry point exposes the same information through
`describe_generated_fixture()` so generation, validation, and runtime loading
can reject semantic or shape drift. These are demo-only offline-fixture
contracts. An ordinary live parser implements the standard capability hooks and
does not need `describe_generated_fixture()` or
`generated_projection_policy`.

The final node packs contain only local status, local past logs, and
plug-in-readable local evidence. Private authoring medium IDs and global
participant lists are never copied into a node dump or its topology
projection. Shared connectivity is reconstructed from matching attachment
claims made independently by the participating nodes.

### Past-time reconstruction checkpoints

The canonical save uses `2025-10-05 16:00:00 UTC` as its base and a `+720 s`
capture point. In the node workspace, compare moments immediately before and
after these authoring offsets; per-node clock offsets remain visible in the
generated evidence.

The fabric page can reconstruct the same revisions. After its first query, use
the **Reconstructed status** bar above the link graph: click or drag, or focus
the range control and use the arrow, **Home**, and **End** keys. Its amber
handle is the selected time and its cyan notch is the time still applied to the
graph; releasing or finishing a keyboard change starts the reconstruction
after a short debounce. With the default relative basis, an offset is applied
separately to each node's projection watermark and does not imply simultaneous
wall clocks. Select **Absolute UTC instant** in the reconstruction controls
when you want one global scenario instant. A pending change between these two
bases must be reconstructed before the bar can use the new axis.

| Offset | Expected reconstruction |
|---|---|
| `+30 s` / `+210 s` / `+270 s` | PE-A's temporary blue route appears, disappears, and appears again. |
| `+90.050 s` / `+96 s` / `+108 s` | P1 records carrier down. P2 records a stale carrier notice and a failed withdrawal, so P2's existing interface and route state remain unchanged. |
| `+180 s` / `+181 s` / `+300 s` / `+304 s` | PE-D's local subinterface and adjacency detach and later reattach independently. |
| `+360 s` | PE-B retains its prior next hop after a failed update attempt. |
| `+420 s` to `+535 s` | Physical failure, delayed observations, withdrawal, and staggered restoration create a temporary Ottawa cross-node inconsistency. |
| `+610 s` | PE-A's final successful next-hop update is present in the capture snapshot. |

For each executable case, `coverage.json` carries all forward and reverse
`candidate_paths`. Every involved node's forwarding row carries
`directional_decisions` keyed by direction and candidate occurrence
(`candidate_id` plus `visit_index`). The plug-in owns the candidate sequence,
active/primary/alternative semantics, state, disposition, and
`resolution_text`. A non-local next hop also supplies an exact
`connectivity_domain` reference, its matcher/key, and local/remote attachment
resource IDs. Core compares those opaque declarations with the current topology
snapshot and accepts a boundary only when exactly one usable domain and exactly
one current usable attachment on each side match. It performs no prefix, VLAN,
address, label, or node-pair inference.

`coverage.json` is generated from the versioned `COVERAGE_CASES` registry. The
current registry contains 35 cases: 18 route, eight packet, four topology, and
five temporal. The 26 route and packet entries map to executable route
scenarios with node/revision-qualified route and forwarding evidence; packet
entries also carry a generated packet declaration. Validation rejects missing
or mismatched evidence rather than falling back to a separate hand-written
route result.

The four topology cases use `topology_claim` evidence copied from the exact
generated claim: attachment resource, matcher and segment key, classification,
validity, and calculation metadata. The five temporal cases use
`temporal_event` evidence resolved from the matching generated phase and event
shape, including its real event UID, resource, outcome, and `state_changed`
value. The installed policy validates these discriminated shapes at generation
and lazy runtime load; archive validation additionally proves node/revision
namespacing.

The single-node workspace advertises the selected node's bounded route choices
with opaque `route_id` values and executable basis kinds. The generic core
frontend submits only one advertised identity; it does not hard-code or infer a
destination. This is currently a coordinator adapter over generated plug-in
projection rows, not a second plug-in hook.

Generated route rows whose `scenario_id` is null are inventory observations,
such as a local attachment route. They remain available in the all-node route
table with `traceable: false`, an empty `trace_query`, and a reason. The browser
must not turn one into a cross-node trace by inventing a candidate path.

## Advanced forwarding boundary

This small plug-in intentionally stops at status parsing. A plug-in that adds
forwarding supplies typed `ForwardingCandidateConstraint` and
`ForwardingTraversalStateKey` values, exact packet transitions, local endpoint
attachments, terminal evidence, and device-owned policy or disposition
semantics. Core evaluates bounded traversal, exact repeated states, endpoint
reachability, and packet continuity.

Test every advertised optional hook through `PluginCapabilityExecutor` so
manifest gating, bounded reads/results, schema references, and recoverable
versus fatal diagnostics exercise the same core boundary as a future host
integration. Do not call those hooks directly in an author golden test.

Advanced implementations must distinguish complete known-empty scope data from
incomplete scope evidence. They must also keep immutable packet endpoints
separate from a trace start: a return path can reach the source attachment
without revisiting a transit forward start. See “Route endpoints and trace
starts”, “Packet transformations and trace-time forwarding”, and “Forwarding
loops and ingress-dependent policy” in the
[`plugin-author-quickstart.md`](../docs/plugin-author-quickstart.md) before
advertising those capabilities.
