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
python -m pip install -e ".[web]"
python -m pip install -e "./demo"
.\scripts\launch_demo.cmd -NoBrowser
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
path to the core. For an already generated assembly, load the installed
plug-in entry point directly:

```powershell
router-dump-analyzer --plugin demo_router `
  --input demo/fixtures/router-state-lab-demo.tgz `
  --no-browser
```

During source-tree development, bypass installed entry-point discovery without
changing ownership:

```powershell
python -m router_dump_analyzer `
  --plugin-module rsl_demo_plugin `
  --input demo/fixtures/router-state-lab-demo.tgz `
  --no-browser
```

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
{"kind":"interface","captured_at_ns":1759680000000000000,"ifindex":7,"name":"xe-0/0/0","admin_status":"up","oper_status":"up","description":"core uplink"}
```

The plug-in owns that JSON vocabulary, the typed `ifindex` key, platform and
version matching, status normalization, resource descriptors, evidence,
bounded hover text, and safe source-record `copy_text`. The example assumes
that `ifindex` is stable within one analysis revision and maps `oper_status=up`
to healthy, `down` to error, and other accepted values to unknown.

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

## Optional runtime capability

The tiny parser can be installed and validated without starting a server. The
comprehensive generated assembly additionally needs an input adapter, so the
example plug-in exposes an optional `plugin.runtime` capability with
`capability_id = "router_dump_analyzer.runtime.v1"`.

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

The first three are required by the web runtime; the last three may be `None`
when a plug-in does not support those views. The core enters and closes the
session, constructs `NormalizedDataService`, and owns resource/state,
relationship, table, dashboard, range, redaction, and client-projection
algorithms. A runtime provider must not return a FastAPI app, `APIRouter`,
middleware, templates, frontend code, or a substitute query engine.

`plugin.runtime` is optional for ordinary parse-only plug-ins:
`router-dump-plugin-validate` validates their normal `AnalyzerPlugin`
contracts without it. It is required only when that plug-in is selected by the
core `router-dump-analyzer` web command.

## Generated mock dumps

The small JSONL file is a conformance vector, not the comprehensive mock dump.
It is rendered from the plug-in-owned `CONFORMANCE_STATUS_RECORDS`; verification
fails if the checked-in bytes drift. Full single-node and multi-node packets
are produced by the same deterministic generator. Use the canonical generation
and verification commands in the
[`samples/README.md`](../samples/README.md#generate); this section owns only the
demo-specific projection, evidence, and runtime-loading contract.

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

Advanced implementations must distinguish complete known-empty scope data from
incomplete scope evidence. They must also keep immutable packet endpoints
separate from a trace start: a return path can reach the source attachment
without revisiting a transit forward start. See “Route endpoints and trace
starts”, “Packet transformations and trace-time forwarding”, and “Forwarding
loops and ingress-dependent policy” in the
[`plugin-author-quickstart.md`](../docs/plugin-author-quickstart.md) before
advertising those capabilities.
