# Router State Lab

**Explore how router state changes across time, layers, and devices.**

Router State Lab is a runnable design and conformance demo for a temporal router
dump analyzer. It turns heterogeneous status tables and logs into resources,
events, relationships, topology, and route explanations that can be inspected at
any point in a capture. The protocol-neutral analyzer core owns the only
server executable, FastAPI application, HTTP routes, lifecycle, and generic
browser frontend. The separately packaged demo is loaded by that executable as an
example plug-in and supplies only device semantics, a fixture input adapter,
and the fixture generator.

The repository includes one deterministic ten-node demo assembly. **Every
node contains a 1,250,000-event and 7,500-resource scalable baseline plus its
explicit authored history and final resources** and can be opened either as an
individual temporal workspace or as a member of the same multi-node topology
and route trace. The declared coverage includes IS-IS, IP routing, SR-MPLS,
SRv6, EVPN multihoming, MPLS/L2/L3 VPNs, failover, packet evolution, and
cross-layer inconsistency.

> [!IMPORTANT]
> The bundled launchers review the generated synthetic dump. The core also has
> an opt-in durable single-host control plane for upload queues, multi-plug-in
> selection, tenant/project/workspace catalogs, multi-revision sessions, and
> human review. Its HTTP boundary accepts a host-supplied verified identity and
> enforces roles/scopes, but the built-in local adapter is not authentication.
> The project does not provide TLS, distributed storage, or a hardened
> plug-in sandbox/container. Durable probe and ingestion calls do run in
> bounded, killable child processes by default, but those children inherit the
> host user's operating-system privileges and are fault isolation, not a
> security boundary.
> Every newly published durable revision also records an immutable execution
> plan for the exact plug-in artifact, configuration digest, schema,
> capabilities, role, and optional decoder that interpreted it. Legacy
> revisions remain explicit when that provenance is unavailable.
> A core-owned plan-bound capability router can then compose different
> plug-ins, versions, and configured instances across nodes without choosing
> by install order. It executes only an exact provider named by that revision's
> plan and retains the complete producer pin with every result.

## Start here

| Goal | Go to |
|---|---|
| Run the bundled demo | [Run the demo](#run-the-demo) |
| Learn what to inspect | [What to try](#what-to-try) |
| Exercise durable workflows and offline evidence tooling | [Core demo walkthrough and validation](docs/demo-core-coverage.md) |
| Compare physical connectivity with VPN membership | [VPN topology samples](demo/README.md#vpn-topology-samples) |
| Inspect conflicting observations from different routers | [Cross-node inconsistency samples](demo/README.md#cross-node-inconsistency-samples) |
| Build a device plug-in | [Plug-in author quickstart](docs/plugin-author-quickstart.md) |
| Validate individual and combined plug-in APIs | [API validation map and repository skills](docs/plugin-api-validation.md) |
| Use the Python API from a typed client | [Typed Python API](#typed-python-api) |
| Run durable uploads, sessions, or review | [Durable control plane](docs/control-plane.md) |
| Integrate with the API | [API payload contract](docs/api-contract.md) |
| Understand the design | [Architecture and library decisions](docs/architecture.md) |
| Regenerate sample data | [Sample input guide](samples/README.md) |
| Author custom temporal dump scenarios | [Standalone State Dump Generator](state-dump-generator/README.md) |

The [standalone scenario studio](state-dump-generator/README.md) lets you draw
private physical ground truth, schedule delayed or faulty node-local
observations, and generate topology-free dump files. Its saved project,
[`demo/router-state-lab-default.scenario.json`](demo/router-state-lab-default.scenario.json),
is also the canonical authoring source for future bundled demo dumps. The
authoring tool, demo materializer, and analyzer remain separate packages: the
demo reads that JSON through a small standard-library adapter and never imports
the authoring tool. Attachment `properties` in that save are always
authoring-only; only an explicit `node_local_observation` may supply exported
node evidence. A top-level attachment resource ID is used only as the local
identity fallback.

## Run the demo

The normal launcher serves both the FastAPI backend and browser application.
Node.js is not required unless you want to develop the frontend separately.

### Windows

Install [Miniconda](https://docs.conda.io/miniconda.html) or
Anaconda, then run these commands from PowerShell in the repository root:

```powershell
.\scripts\setup_demo.cmd
.\scripts\launch_demo.cmd
```

The setup script creates or updates the Python 3.12 environment and runs the
core and demo Python suites. It installs the core and demo as separate editable
distributions; the core distribution owns the generic browser assets, while
its optional `web` extra supplies FastAPI and Uvicorn hosting support. The
synthetic plug-in and fixtures remain demo-only. The launcher enables the
local durable control plane by default at `.runtime\control-plane`; use
`-ControlPlaneDir PATH` to choose another state directory. On Windows, its
resolved path must fit within 131 UTF-16 code units so the complete private
ingestion staging path remains within the portable legacy-compatible budget,
even on hosts with optional long-path support. The listener remains loopback-only
unless the explicitly unsafe
`-TrustControlPlaneHeaders` development switch is also supplied. Before every
normal launch, a fast outer-archive check confirms that the input contains the
complete
canonical full-scale node set, one checksum-matching generated dump pack per
node, the SHA-256 digest of the canonical authoring save, and the fingerprint
of the demo materializer that interpreted it. A missing archive is generated,
while an unsuitable, source-stale, or materializer-stale generator-owned
archive is rebuilt atomically. An
unowned file, symlink, directory, or unreadable archive at the preferred path
is never overwritten; the launcher preserves it and selects the fixed
`router-state-lab-demo.generated.tgz` sibling before opening
`http://127.0.0.1:8765`.

If port 8765 is occupied:

```powershell
.\scripts\launch_demo.cmd -Port 8876 -NoBrowser
```

To rebuild the complete fixture:

```powershell
.\scripts\launch_demo.cmd -RebuildFixture -NoBrowser
```

Normal launches reuse an archive only after that cheap multi-node suitability
check; rebuilding already includes the generator's integrity validation. To
also decode and structurally validate the existing node packs before starting,
add `-ValidateFixture`. The launcher passes the exact preferred or recovery
path selected by the generator to the core. The server then stays attached to
the terminal by design; press `Ctrl+C` to stop it.

For a manual core-owned launch, activate the environment created by the setup
script, then ask the generator for the safe preferred or recovery path before
starting the server:

```powershell
conda activate router-dump-analyzer-demo
$demoArchive = python -X utf8 -m rsl_demo_generator `
  --ensure-launchable demo/fixtures/router-state-lab-demo.tgz --path-only
router-dump-analyzer --plugin demo_router `
  --input $demoArchive `
  --control-plane-dir .\.runtime\control-plane `
  --port 8876 --no-browser
```

In that activated environment, the same loader can address the source-tree
module directly:

```powershell
$demoArchive = python -X utf8 -m rsl_demo_generator `
  --ensure-launchable demo/fixtures/router-state-lab-demo.tgz --path-only
python -m router_dump_analyzer `
  --plugin-module rsl_demo_plugin `
  --input $demoArchive `
  --control-plane-dir .\.runtime\control-plane `
  --plugin-composition-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment `
  --no-browser
```

The ordinary selector owns the immediate startup input. The separate
`--plugin-composition-deployment-module` descriptor owns uploads processed by
the embedded durable control plane and is accepted only with
`--control-plane-dir`; standalone durable commands use
`--plugin-deployment-module` instead.

`--plugin` selects an installed `router_dump_analyzer.plugins` entry point.
`--plugin-module PACKAGE[:ATTRIBUTE]` imports a module-level instance directly;
the attribute defaults to `plugin`. Both modes use the same core server.

### Linux or WSL

Keep a WSL checkout on its native Linux filesystem rather than under `/mnt/c`
for better filesystem performance:

```bash
./scripts/bootstrap_wsl.sh
./scripts/launch_demo.sh
```

The bootstrap uses an existing compatible Conda installation when available.
Its automatic Miniforge installation currently supports x86_64 Linux/WSL.

The Linux launcher does not open a browser by default. Open
`http://127.0.0.1:8765`, or choose another port:

```bash
./scripts/launch_demo.sh --port 8876
```

The WSL launcher performs the same automatic multi-node suitability check.
Use `--validate-fixture` for the additional full integrity check or
`--rebuild-fixture` to regenerate and internally validate the corpus. The
server stays in the foreground until you press `Ctrl+C`. It enables durable
local state at `.runtime/control-plane`; choose another directory with
`--control-plane-dir PATH`. A non-loopback `--host` also requires the explicit
development-only `--trust-control-plane-headers` override.

### Main URLs

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8765/` | Multi-node topology and route tracing |
| `http://127.0.0.1:8765/topology` | Compatibility alias for the topology home |
| `http://127.0.0.1:8765/node` | Individual-node temporal workspace |
| `http://127.0.0.1:8765/analysis` | Private workspace analysis lifecycle, evidence report, and explicit human proposal review |
| `http://127.0.0.1:8765/manage` | Durable project/workspace catalog, imports, sessions, scoped revision inspection, and role-gated administration |
| `http://127.0.0.1:8765/docs` | Interactive API documentation; available only after a loopback launch with `--expose-api-docs` |
| `http://127.0.0.1:8765/health` | Server and fixture health |
| `http://127.0.0.1:8765/v1/analysis-load` | Non-sensitive progress for archive reading, revision loading/indexing, provider validation, topology reconstruction, route tables, and tracing |
| `http://127.0.0.1:8765/v1/control-plane/health` | Session-independent durable worker and queue health |
| `http://127.0.0.1:8765/v1/control-plane/diagnostics/operational-events` | Protected operational diagnostics; requires `control-plane:instance-operator` |
| `http://127.0.0.1:8765/v1/control-plane/context` | Durable control-plane context; requires `X-Tenant-ID` and an enabled state directory (the bundled launcher enables one) |

The topology page is the normal entry point. Select a device or endpoint there
to open its node workspace with the same reconstruction context.
Both pages display the same sticky parsing indicator while a cold node revision
is being materialized. It shows a percentage only when the loader supplied a
real bounded total; otherwise it remains indeterminate and reports the current
generic phase and processed-record count. The frontend host deliberately starts
before ordinary runtime-v2 parser ingestion and lets its first workspace request
perform that tracked load. API-only startup remains synchronous and fail-fast;
there is no detached parsing worker left running at shutdown.
The canonical 1.25M-event node currently materializes in roughly 30 seconds and
uses several gigabytes of RAM on the reference Windows development machine.
The demo retains only one materialized node at a time; opening another node may
therefore reparse an evicted history. First generation also needs several
gigabytes of temporary disk while its bounded node workers assemble the ten
packs. These are deliberate scale-test costs, not production sizing guidance.
The analysis application keeps OpenAPI JSON, Swagger UI, and ReDoc disabled by
default. A loopback launch may opt in with `--expose-api-docs`; the command
rejects that option for `0.0.0.0`, `::`, and every other non-loopback bind.

## What to try

1. **Trace both directions.** Choose the packet source, destination, VRF, and
   optionally a different starting/observation node. Forward success means the
   destination is reached; return success means the source is reached, even when
   the return never revisits a transit starting node. Switch between all
   candidates and a focused path to inspect active, standby, dead, incomplete,
   and best-effort resolutions. If only some selected active branches reach the
   endpoint, the result stays visibly partial instead of being called healthy.
   The review scenarios also include endpoint
   reachability from a transit start, a recursive next-hop cycle, a cross-node
   forwarding loop, and an EVPN split-horizon policy block; the last keeps the
   intentionally rejected candidate visible instead of calling it a dead link.
2. **Explore the network model.** Toggle subnets, interfaces, subinterfaces,
   VLANs, and LAGs. Compare physical/subnet connectivity with the focused route
   graph and inspect how each inferred element was calculated.
3. **Reconstruct another fabric moment.** After the first topology
   reconstruction, use the **Reconstructed status** bar immediately above the
   link graph. Click or drag its handle, or focus it and use the arrow,
   **Home**, and **End** keys. The amber handle is the newly selected moment;
   the cyan notch remains at the moment currently shown by the graph until the
   short automatic reconstruction finishes. The control is disabled while a
   reconstruction is running. In **Relative to each watermark** mode the axis
   is one common offset from each selected node's watermark, not a claim that
   their wall clocks are simultaneous. If you change between absolute and
   relative time in the query controls, run that reconstruction before using
   the bar on the new axis.
4. **Travel through one node's history.** Open a node, click a moment, or drag
   horizontally across the timeline to select a range. The resource state,
   relationships, findings, and normalized event list follow the selected
   time. Use **Zoom range** (or `Z`/`Enter`) to fit that duration without
   changing its endpoints. The timeline toolbar also provides pointer-centered
   zoom, centering, capture fit, previous/next viewport history, and horizontal
   trackpad or Shift+wheel panning. Right-click
   a lane or event—or open **Actions** for touch and keyboard use—to inspect or
   reveal an item, set either range boundary, select the visible duration, copy
   time coordinates, focus or hide a resource, and clear the current selection.
   `+`, `-`, `0`, `C`, `Alt+Left`, `Alt+Right`, and `Shift+F10` provide the same
   common viewport operations without requiring a drag gesture.
5. **Follow causality.** Expand temporal correlations to see dependencies and
   dependents. Ctrl-click a timeline mark to find its normalized log row; in the
   log, use ordinary click/Ctrl-click/Shift-click/drag selection and
   double-click or **Reveal in timeline** to navigate back. Press **Esc** to
   clear the focused selection, event, moment, or range.
6. **Inspect scale without losing detail.** On any node, browse the virtualized
   1.25M-plus-event log, zoom-aware density lane, 7.5K-plus-resource tables,
   unmatched-log lanes, route tables, neighbor data, and plug-in-defined
   dashboards. Local inventory rows without a plug-in-declared cross-node
   candidate remain visible but explicitly non-traceable.
7. **Resolve a node-local route.** In the node workspace, choose one of that
   node plug-in's advertised route decisions and basis values. The browser does
   not invent a destination or silently fall back to another node's resolver.
8. **Look for disagreement.** Review delayed or failed updates, changing next
   hops, asymmetric forwarding, and differences between control-plane,
   forwarding, and hardware-layer reachability.
9. **Persist a review.** Use the [runnable parser review example](demo/README.md#durable-review-with-the-parser-example).
   The large generated assembly has no durable-ingestion adapter; its markers
   remain browser-local. The parser example admits and opens the same small
   input in one project/workspace; starting a browser does not publish inputs.
   Then expand **Durable review** above the normalized event log and enter
   explicit tenant, project, workspace, and reviewer IDs. The page labels this
   as trusted-header local development and resolves its active runtime
   revision to exactly one catalog revision. If none or more than one match,
   it keeps markers browser-only and performs no durable writes. Once
   connected, select event/source rows to add or remove markers; select two or
   more events to create a manual correlation. A read-only identity can still
   inspect durable markers and generate reports, but mutation controls stay
   disabled. Choose explicit revisions, a mutable session, or an immutable
   session snapshot when copying or downloading the AI-friendly correlation
   report. Ambiguous writes keep their retry identity across browser reloads;
   the panel can discard unresolved writes for the connected scope or, with an
   explicit warning, reset every browser scope. The node page still renders
   only its active revision.

Topology and route-path graphs support node dragging, background panning,
touchpad gestures, pinch zoom, and Ctrl-wheel zoom. Hover or keyboard-focus
interactive elements for provenance, status, resolution, and inference details.

## The bundled scenario

One generated outer TGZ is the complete demo input. It contains ten independently
captured node TGZs, each with raw synthetic status and log containers, canonical
normalized history, and the projections used by both the node and fabric
workspaces. Topology and route views therefore use the same generated revisions
as the node view rather than a second hand-written fixture.

### Edit and regenerate the canonical scenario

The human-editable source is
[`demo/router-state-lab-default.scenario.json`](demo/router-state-lab-default.scenario.json).
Edit it in the independent GNS2-style studio, not in generated TGZ files. From
the repository root, these PowerShell commands install the authoring tool,
validate the save, and open it for visual preview:

```powershell
python -m pip install -e .\state-dump-generator
python -m state_dump_generator validate .\demo\router-state-lab-default.scenario.json
python -m state_dump_generator serve --open
```

In the editor, click **Open** and choose
`demo/router-state-lab-default.scenario.json`. Move the scenario-time control
to preview physical truth and the scheduled node-local observations. **Save**
downloads a new project file; review it, then intentionally replace the
canonical JSON in the checkout.

The independent tool can compile a small, neutral assembly directly:

```powershell
python -m state_dump_generator generate `
  .\demo\router-state-lab-default.scenario.json `
  --output .\artifacts\router-state-lab-default.node-dumps.tgz
```

That neutral archive is useful for checking authoring semantics, but it is not
the full Router State Lab fixture. After running the normal demo setup, use the
separate demo materializer to add deterministic scale data and plug-in
projections, verify the source and materializer fingerprints, and launch it:

```powershell
python -X utf8 -m rsl_demo_generator `
  --output .\demo\fixtures\router-state-lab-demo.tgz
python -X utf8 -m rsl_demo_generator `
  --check-launchable .\demo\fixtures\router-state-lab-demo.tgz
.\scripts\launch_demo.cmd -NoBrowser
```

The demo adapter uses only Python's standard library to read the saved file.
It derives shared domains by matching repeated node-local attachment evidence,
then adds enough distinct deterministic filler to reach the configured
1,250,000-event and 7,500-resource baseline per node; explicit authored events
and final resources are appended. Private medium IDs and global participant
lists are authoring truth: neither the independent output nor the full demo's
final node dumps contain them. Each node pack contains only that node's status,
logs, and plug-in-readable local evidence.

Useful past-time checkpoints are relative to the saved scenario's base time
(`2025-10-05 16:00:00 UTC`). Node-local dump timestamps also include each
router's declared clock offset.

| Authoring time | What to compare |
|---|---|
| `+30 s`, `+210 s`, `+270 s` | On PE-A, `route:blue:198.51.100.0/30` is created, removed, then recreated. |
| `+90.050 s` through `+240.100 s` | P1 observes `Ethernet3/1` down and later up; P2's `+96 s` carrier event is stale and its `+108 s` route withdrawal fails, so neither changes P2's prior state. |
| `+180 s` through `+304 s` | PE-D locally removes its VLAN subinterface and adjacency, then restores them at different moments. |
| `+360 s` | PE-B logs a failed next-hop update; the previously installed next hop remains the reconstructed state. |
| `+420 s` through `+535 s` | The Ottawa link changes physically first, node C and P2 observe it at different times, and interface, adjacency, and route recovery remain temporarily inconsistent. |
| `+610 s` | PE-A performs the final successful next-hop change visible at capture time. |

See the [demo guide](demo/README.md#generated-mock-dumps) for the current
`demo.example-router` projection and evidence contract, and the
[sample-input guide](samples/README.md#generate) for the canonical generation
and verification commands.

| Dimension | Included coverage |
|---|---|
| Scale | 10 node revisions; a 1,250,000-event and 7,500-resource baseline plus node-local authored rows, with at least 1,000,000 real state-changing events per node |
| Protocols | Connected and static routes, IPv4/IPv6 unicast, IS-IS, SR-MPLS, SRv6, MPLS transport/L3VPN, and EVPN types 2 and 5 |
| Multi-node route model | Ten available assembly members, shared and external subnets, VLAN subinterfaces, LAGs, physical ports, EVPN Ethernet Segments, multipath, dead paths, incomplete paths, and bidirectional endpoint reachability |
| Resource history | Forwarding Groups, ETGs with ETE paths, standalone DTEs, Virtual Interfaces, Glue, neighbors, IP routing, and hardware objects |
| Change waves | Single-home creation, multihome expansion, mass ES withdrawal and failover, mass restore, and distinct next-hop churn |
| Failure cases | Recursive and cross-node loops, split-horizon policy exclusion, hop/recursion limits, dead candidates, stale FIB state, cross-layer mismatch, missing intermediate resolution, one-way forwarding, and clock uncertainty |

The packet cases exercise the core's protocol-neutral packet-evolution model:
native IP, SR-MPLS/PHP, L3VPN labels, SRv6, IP-in-IP, nested VPN, MTU failure,
and user steering.

Each selected node corpus is indexed on demand. Timeline, graph, event-log, and table
queries are bounded or virtualized rather than sending the entire dataset to the
browser. A content- and projection-keyed SQLite sidecar caches only client-safe
derived search text; raw and plug-in-declared sensitive values are not indexed.

## How the design is divided

The central rule is simple: the core owns generic temporal machinery; plug-ins
own device and protocol meaning.

| Owner | Responsibilities |
|---|---|
| Core | The `router-dump-analyzer`, API-only `router-dump-server`, `router-dump-ingest`, `router-dump-maintain`, and read-only `router-dump-health` executables, plug-in loading, FastAPI routes and lifecycle, frontend hosting, tenant/project/workspace catalog, immutable fixtures and revisions, mutable multi-revision sessions, immutable session snapshots, durable upload queue and selection, admission quotas, bounded audited retention, review annotations and reports, safe archive inventory, source records, generic temporal storage, uncertainty, bounded queries, pagination, API contracts, collision-safe client publication and redaction, exact connectivity-domain/attachment joins over plug-in-declared keys, conservative cross-node corroboration, LPM, bounded recursive/multipath traversal, exact packet-state continuity and MTU arithmetic over matching declared bases, immutable flow direction, exact endpoint-goal and typed-policy comparison, bidirectional aggregation, cycle/limit handling, and the reusable browser application |
| Device plug-ins | Dump recognition, input parsing, resource types and typed/compound keys, state transitions, relationships, forwarding-object projection, candidate paths and directional decisions, candidate rank/group semantics, connectivity-domain matcher/key meaning, packet-layer/action/overhead and disposition semantics, typed policy scopes, endpoint attachments and local terminal classification, topology classifications, consistency rules, route-resolution text, icons, and dashboard descriptors |
| Federation/linker plug-ins | Matching endpoint and boundary claims between members, preserving or explicitly mapping compatible packet/scope contracts, and explaining inter-node connectivity without assuming every device uses the same plug-in |

The core never turns missing evidence into invented state. If forward history,
clock alignment, or cross-layer evidence is insufficient, the result remains
`unknown`, `ambiguous`, `incomplete`, or explicitly best-effort.

See the [architecture](docs/architecture.md) for the complete ownership model,
temporal algorithms, storage recommendation, security boundary, and delivery
sequence. The dated
[advanced route-trace audit](docs/advanced-route-trace-audit-2026-07-25.md)
preserves the packet-boundary and scenario-coverage evidence from its audited
revision; use the current architecture, contracts, and tests for present
behavior and remaining work.

## Build a device plug-in

For the shortest working path, use these resources:

- **Start:** [Plug-in author quickstart](docs/plugin-author-quickstart.md)
- **Copy:** [Demo plug-in teaching slice](demo/README.md)
- **Extend:** [Detailed author guide](docs/plugin-author-guide.md)
- **Reference:** [Normative plug-in contract](docs/plugin-contract.md)

The quickstart is the single copy-paste workflow for installing and validating
the known-good example, including
`router-dump-plugin-validate demo_router`. It also explains what the generic
validator checks and what remains the responsibility of the plug-in's golden
tests. A production device plug-in depends only on
`router-dump-analyzer-core`; the demo distribution is a working reference, not
a runtime dependency. Ordinary parser plug-ins need no path-opening runtime:
the core inventories the input, calls their standard discovery/parser hooks,
validates the results, and serves the basic normalized workspace through
runtime v2. The bundled 1,250,000-event-per-node archive is generated and keeps
its runtime-v1 fixture adapter for compatibility.

For advanced reducers, event correlation, revision relationship projection,
consistency, topology, or forwarding, host-side tests call the root-exported
`PluginCapabilityExecutor`. It is the
bounded, schema-validating caller for optional hooks. Production coordinators
route those calls through `PlanBoundCapabilityRouter`, so heterogeneous nodes
and multiple configured instances retain exact revision provenance instead of
using install order. Historical releases may retain one logical instance ID;
a configuration change receives a new ID. Neither facility makes the currently unavailable
runtime-v2 temporal, topology, or route HTTP providers appear.

Durable ingestion now materializes declared revision-scoped relationships and
then consistency checks before it hashes or publishes a dataset. The primary
parser participates when it declares `RELATIONSHIP_PROJECTION` or
`CONSISTENCY_CHECK`; explicitly composed auxiliaries require the corresponding
`REVISION_RELATIONSHIP_PROJECTION_ROLE` or `REVISION_CONSISTENCY_ROLE`.
Every projector sees the same immutable base world, while consistency sees the
augmented world. Core binds declarations to the exact basis and provider,
keeps endpoint identities distinct, deduplicates identical claims, and
preserves conflicts as ambiguity rather than choosing by provider order.
Auxiliaries may keep their own schemas; a private coordinator boundary validates
their scheduled declarations under the primary revision schema without adding
a public schema-override API. Perspective-qualified edges remain distinct, and
explicit parser relationships stay authoritative over projections at the same
qualified edge.
Different status perspectives also retain independent resource state: core
does not combine intended and observed fields, and an ambiguous singular view
stays unknown instead of selecting an arbitrary perspective.
Results are immutable, plan-bound, bounded, and queryable in the stored
revision. A failed projector or rule cannot publish a partial revision.
Legacy consistency revisions are labeled `not_materialized`, while revisions
predating relationship projection have no projection envelope; neither is
silently analyzed with today's plug-in code. Durable/admin records retain exact evidence
locators for offline review; browser and public HTTP projections use closed
core evidence shapes and omit every raw locator. Only plug-in-owned property
payloads pass through descriptor-sensitive redaction.

The maintained author smoke path is:

```powershell
python -m pip install -e ".[test,web]"
python -m pip install -e demo
python -X utf8 -m rsl_demo_generator `
  --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
router-dump-plugin-validate demo_router `
  --artifact demo/fixtures/minimal-status.jsonl `
  --node-hint router-1 `
  --metadata platform=demo-router-os `
  --metadata software_version=1
python -m unittest tests.test_artifact_core tests.test_ingestion tests.test_capability_executor tests.test_capability_router tests.test_relationship_projection_materialization tests.test_relationship_projection_ingestion tests.test_consistency_materialization tests.test_consistency_ingestion tests.test_revision_world -v
python -m unittest tests.test_reconstruction_boundaries tests.test_shared_core_contracts tests.test_reconstruction_truth tests.test_route_packet_projection -v
python -m unittest tests.test_property_visibility tests.test_resource_property_policy tests.test_normalized_data_service -v
python -m unittest discover -s demo/tests -v
python -m unittest discover -s state-dump-generator/tests `
  -p "test_runtime_v2_vectors.py" -v
```

See the [demo guide’s compact corpus section](demo/README.md#compact-runtime-v2-conformance-corpus)
for the separate generate/verify commands and the currently executable subset.

## Durable ingestion and review

Open `/manage` on the normal frontend-hosting analyzer to create projects and
workspaces, upload supported dumps, inspect parser candidates/progress, and
manage sessions and immutable snapshots. Connect with an authorized tenant and
principal; these fields stay only in the current page, not URLs or browser
storage. Headers are not authentication: the deployment verifies identity.
Write, tenant-admin, and instance-operator controls are separately gated.
The bundled startup demo is not automatically published into this catalog.

**Inspect analysis** reads an explicit published revision, session member, or
snapshot inside `/manage`. It pages summary, resources, events, relationship
observations, and materialized findings with exact nanosecond controls. It
does not switch the server's startup input or open arbitrary durable revisions
in the existing Fabric/Node route and topology runtime. Those advanced
capabilities remain unavailable in this durable inspector. Deployment settings
are read-only; disclosure-policy changes and retention require explicit
administrator confirmation, and retention first requires a bounded preview.
See the [management guide](docs/control-plane.md#management-console-and-durable-inspection)
for workflows, uncertain-write handling, and current scaling limits.

The optional control plane keeps uploaded fixtures and published revisions in
an explicit `tenant -> project -> workspace` catalog. A mutable session selects
any number of exact fixture/revision pairs—including several revisions of the
same node—while an immutable snapshot freezes one selected vector. Review
annotations and manual event correlations live in a separate mutable overlay,
so they never rewrite normalized history. Reports are deterministic,
AI-friendly canonical JSON or Markdown and keep plug-in facts, human
assertions, and conservative core corroboration separate. Each report requires
one explicit bounded revision, session, or snapshot selector; omission never
widens to the complete workspace. The v2 report wire encodes every declared
core-owned nanosecond as a decimal string while preserving opaque plug-in
payload keys and JSON value types. Cross-clock comparisons are labeled unknown
rather than inventing an order. Unicode line/paragraph separators, NEL, every
non-ASCII space separator (including NBSP), ZWSP, BOM, directional controls,
and assigned blank Hangul fillers, Khmer inherent-vowel characters, the
Braille blank glyph, and Egyptian hieroglyph blanks are made visible as escaped text
throughout AI-facing exports. Combining grapheme joiner, unregistered or
misplaced variation selectors, U+FFFC OBJECT REPLACEMENT CHARACTER, and
private-use characters are also made explicit without rejecting the
surrounding display label. U+FE0E/U+FE0F remain raw only when the immediately
preceding base-selector pair is registered in the vendored Unicode 15 emoji
variation table; each pair inside a ZWJ sequence is checked independently and
repeated selectors on one base do not pass. All selectors remain invalid in
identifiers. ZWNJ and ZWJ retain their shaping semantics. Literal backslash
escape sequences stay distinct from escaped
unsafe characters in canonical reports and their SHA-256 digests. The Khitan small-script filler retains its legitimate cluster-layout
semantics inside visibly anchored text. Corroboration snapshots its
bounded evidence so caller mutation cannot change a completed report.

The core also exports a local-only private-analysis contract layer.
Atomic references bind tenant/workspace scope, immutable fixture and dataset
digests, the exact plug-in execution plan and producer instance, an opaque
locator digest, disclosure class, payload schema, and explicit time basis.
Disclosure-gated envelopes deep-detach bounded canonical JSON and reject
`never_assistant` and cross-workspace decision replay; wire parsers never mint
missing identity digests. Multi-node claims compose several atomic references.
Versioned requests bind the exact revision vector, local runner selection,
policy/instruction digests, the closed read-only tool-catalog digest, the
deployment-owned evidence-service digest, clock, query, and budgets. The core
corpus is independently bounded by entry count and canonical payload bytes
(512 MiB by default, 2 GiB maximum), so operators can size local proprietary
analysis without enabling a network model service. Advisory results contain
citation-backed claims or explicitly unsupported hypotheses and
`assistant_suggested` proposals. The summary is itself a support-labeled claim,
not an uncited text channel; validation accepts citations only from the
references actually disclosed for that request. Typed failures do not carry
arbitrary diagnostics. Core also exports an inert, self-digested catalog
containing exactly `query_evidence`, `read_evidence`, and `analyze_evidence`,
plus typed calls, keyset cursors, page/read/derived results, and payload-free
errors. Those values carry no handler, database/filesystem handle, shell,
network, or live plug-in object. The third tool carries only an exact
node/revision selector, a closed analysis intent,
already-disclosed parent-reference digests, bounded JSON parameters, and an
output ceiling. The model cannot provide evidence payloads or select a plug-in
by package/platform name.
The catalog remains inert, while a separate trusted
`PrivateAnalysisToolService` executes catalog calls for one exact
request. It re-authorizes and re-evaluates current workspace policy per call
and before release, validates every reference against deployment-owned catalog
bindings, conceals foreign or denied reads, detects changed query snapshots,
and atomically enforces cumulative call, unique-reference, and canonical-byte
budgets. Query references join the same request-local citation ledger as read
envelopes. Provider callbacks are contained and cannot leak diagnostics into
tool errors. The default `ControlPlane` revision-evidence composition supplies
the analysis callback: it selects the unique `EVIDENCE_ANALYSIS` provider from
the target revision's retained execution plan, passes only already-disclosed
parent envelopes, and registers the resulting v3 derived reference for exact
request-local rereads. Missing, ambiguous, or stale providers return the
closed `capability_unavailable` result.

`ConfiguredPrivateAnalysisInProcessRunner` now composes one pristine tool
service with an operator-supplied, process-trusted local callback. It binds the
exact runner ID/version/configuration and trusted instruction-profile digest,
admits current workspace access before exposing the request, and gives the
callback only a detached request/catalog context plus a thread-affine gateway
as its supported interface for canonical closed-catalog calls. The callback is
deployment-trusted Python, not an adversarial sandbox guest: deliberate
reflection into, or mutation of, the gateway's private implementation state is
outside this transport's contract and requires the child-process transport.
The callback returns canonical
`PrivateAnalysisResult` JSON; core closes the gateway, rechecks access, then
validates output budgets and every citation against the exact disclosure
ledger. A constant-memory digest chain records call/response identities
without retaining payloads or model text. Core refreshes one detached
last-complete ledger/budget snapshot after tool work and during finalization;
an ordinary snapshot, close, or receipt failure returns a static error without
resetting already consumed calls or disclosed evidence. The transcript records
unsupported private-lease bypasses as unattributed calls rather than pretending
that the disclosure never happened. Cooperative monotonic deadline
checks after result validation discard output that becomes late while parsing,
but this trusted in-process transport cannot
preempt a callback that never returns. It is not a sandbox and adds no public
provider, endpoint, key, network fallback, persistence, HTTP route, shell, or
plug-in authority. The tool service and runner remain ephemeral.

`ConfiguredPrivateAnalysisSubprocessRunner` implements the complementary
killable local-child library boundary. Its launch contract requires a bounded
exact argument tuple whose executable is an absolute non-`.bat`/`.cmd` path,
an absolute working directory, and a complete explicit bounded environment.
On Windows, executable and working-directory components ending in a period or
space are rejected before extension checks so Win32 normalization cannot alter
the digest-bound effective path;
the child is started with `shell=False`, binary pipes, closed unrelated file
descriptors, and no ambient-environment merge or `PATH` executable lookup.
Those inputs, the adapter identity, stderr/reaping limits, and the explicit
`descendant_policy: forbidden` declaration are covered by the launch digest
that the selected runner must bind.

The parent first sends payload-free `HELLO` sequence 0 carrying only the run
digest; only an empty `READY` sequence 1 permits a fresh access check and
`START` sequence 2 with the detached request and closed tool catalog. Later
`TOOL_CALL`, `TOOL_RESULT`/`TOOL_ERROR`, and terminal
`ANALYSIS_RESULT`/`RUNNER_FAILURE` messages use one same-run global sequence.
Every frame is an exact self-digested JSON object serialized as bounded strict
canonical UTF-8 JSON plus exactly one LF. A terminal message is accepted only
after stdin is closed, stdout reaches EOF without another frame, and the child
exits zero before the monotonic deadline.
Deadline precedence is checked before and after lease admission, after typed
tool-call parsing but before provider entry, after provider return, and after
result/transcript/receipt finalization. Ordinary cleanup/finalizer failures
become `runner_failed`; process-control exceptions retain precedence.

Stdout and stderr are drained concurrently; stderr content is discarded and
only its bounded byte count is sealed. Cleanup runs on every exit path: it
signals the pump, applies bounded terminate-then-kill waits while the direct
child remains live, closes stdin/stdout, and lets the stderr helper drain to
EOF before closing stderr; a still-live child instead has stderr closed to
unblock the helper. Both non-daemon helpers are bounded-joined before sealing.
Failure to observe child exit and stopped helpers withholds the receipt and
leaves the durable run behind a cleanup fence. The owning coordinator retains
the exact live process/session handle and retries one bounded cleanup operation
at a time; only confirmed cleanup reseals and releases the withheld receipt.
No PID is persisted or reconstructed. This is fail-closed terminal acceptance,
not an unconditional OS reaping guarantee.
Adapter-created descendants are forbidden because this portable implementation
does not provide a Windows Job Object or process-tree kill guarantee. The child
boundary is killable but is not a filesystem/network/CPU/memory sandbox, so a
deployment must add those OS controls. Neither runner contains a public-provider
SDK, endpoint/key configuration, automatic network fallback, or promotion
workflow. See the
[private AI analysis boundary](docs/private-ai-analysis.md).

Private-analysis runs can now be executed and retained locally without wiring
a public model service. `SqlitePrivateAnalysisRunStore` persists the exact scoped,
multi-revision request; a fenced lease/cancellation lifecycle; write-ahead
evidence-ledger and budget snapshots; a payload-free transport summary; and a
sealed terminal outcome. The `ControlPlane` owns this dedicated database and
protects every referenced revision from catalog retention. Run retention is
bounded and disabled by default, and preserves only payload-free tombstone and
journal commitments after proprietary request/outcome data is purged. It uses
secure deletion and a truncating WAL checkpoint without making a bounded purge
run full-database compaction. Independent active-run guards and live admission
anchors make missing heads fail catalog protection closed. A missing root
binding, missing/truncated database, or replacement database also fails closed
after first initialization. `PrivateAnalysisExecutionCoordinator` now routes a
queued record to one exact registered local runner, maintains its fenced lease,
commits complete accounting before every tool response, observes durable
cancellation, and persists the exact transport-neutral receipt without
automatic retry. The in-process path remains cooperative; the subprocess path
reports cancellation only after its child and helper cleanup is attested.
`ControlPlane` owns the coordinator and an authenticated application service
for listing approved local runners, admitting runs, executing or cancelling
them with optimistic version checks, and reading display-safe terminal reports.
The shipped server configures no runners, so the catalog is empty and execution
is unavailable until deployment composition explicitly registers an approved
local runner with exactly one evidence mode: a trusted spawned process-factory
target, an explicitly cooperative/unbounded trusted-inline compatibility
factory, or the core's revision-evidence policy. Process factories use inert
canonical configuration and bind target, configuration, deployment semantics,
and content-addressed executable identity into the request. Registration
accepts only an exact source-backed module callable, hashes either its
top-level module file or complete import-package scope, and binds its live,
source-declared recursive bytecode, signature/default state, class methods, and
safe static global references. Exact bytecode-referenced helper globals,
static attribute paths, and statically resolvable local imports are followed
recursively even when the helper is in a different package. Fingerprinting
never executes an import to discover authority: a bytecode-referenced local
import must already be loaded by deterministic package initialization.
Function-owned executable state participates too. Callable instances additionally bind bounded canonical
`__dict__`/slot state, behavior-bearing class attributes, and callable or
descriptor dependencies. The shared traversal is cycle-safe and capped at 64
value levels, 32,768 value nodes, 2,048 code objects, and 32 MiB of runtime
value bytes. Source used for local-import analysis is lexically preflighted
against the remaining node budget before CPython constructs its AST. All retained live class and mutable-object snapshots are checked
again after traversal and before the digest is returned. Generated code, unsafe closures, custom builtins, unsupported
mutable state, and dynamic global dereferences fail closed; frozen dataclass
and enum constants are bounded and bound by value. Core retains only the detached
digest, never the callable, path, or bytes, and re-imports and
revalidates that identity immediately before spawn and again in the child
before invocation; module-attribute or file-byte drift fails with a static
outcome. The exact service remains behind bounded canonical IPC and is killed
and reaped on preparation timeout or durable cancellation. The local
model-adapter child uses the same terminal rule. Before either child launch,
core records a payload-free cleanup fence for the exact run and execution. The
fence stores no PID or release secret: it retains only a domain-separated
one-way verifier. The owning coordinator keeps the random 256-bit release
capability beside the exact live service or runner handle, hidden from
representations and diagnostics. A failed reap keeps cleanup retryable and
prevents any durable terminal outcome from being sealed; a model receipt is
withheld until cleanup is confirmed. Generic lease recovery skips the fence,
and only confirmed reap plus that in-memory capability can enter an atomic
terminal transition that removes it; there is no standalone fence-clear API.
If process control interrupts in-process receipt sealing after the callback
returns, core retains the started transcript/accounting snapshot and retries a
`runner_failed` receipt instead of finalizing the run as unstarted. After a
coordinator restart an unmatched fence remains diagnosable and nonterminal
instead of risking a reused PID or treating copied durable fields as authority.
The HTTP surface
accepts
analysis intent only; it derives scope, immutable revision bindings, current
workspace policy, runner configuration, instruction profile, and the closed
tool-catalog digest. It exposes no public-provider configuration, endpoint/key
setting, network fallback, transcript, evidence payload, or executable callback.

After a cleanup-complete terminal report, `/analysis` also supports an explicit
human review step. A reviewer can reject one exact digest-pinned proposal or
write a separate annotation/manual-correlation target and promote it. The model
payload is always read-only and is never copied into that target. Decisions are
durable, actor-attributed, idempotent receipts; a process interruption leaves a
visible pending promotion that resumes only after another explicit,
version-guarded action. Subject existence is proven before reservation under
the review/catalog retention fence. Replaying the decision request cannot
resume work. The scope-bound request digest deterministically projects the
decision and overlay-target IDs, and every store read verifies them before
deriving the overlay key. A separately stored HMAC key authenticates the
reservation, so coherent SQLite rewrites cannot mint new authority; back up the
key file and proposal-review database together. Recovery rechecks that authority and the exact overlay,
and pending decisions protect their receipts and revision references from
retention. The browser accepts decision authority only from the same frozen
report; an ambiguous mutation requires reload and inspection rather than
guessing which human intent won. See the
[private AI analysis boundary](docs/private-ai-analysis.md) for the trust model
and [API payload contract](docs/api-contract.md) for exact bodies.

For a headless multi-fixture run:

```powershell
$env:PYTHONUTF8 = "1"
router-dump-ingest --plugin-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment `
  --state-dir .\.runtime\control-plane `
  --tenant example-tenant `
  --project lab-project `
  --workspace regression-2026-07 `
  --input .\demo\fixtures\minimal-status.jsonl `
  --node-hint router-1 `
  --output .\artifacts\ingestion-result.json `
  --pretty
```

Repeat `--input` for additional fixtures. The optional node hint and bounded
JSON metadata are plug-in-visible parsing inputs; catalog and identity scope
remain core-private. Run the frontend-free API service with an
allowlisted installed plug-in and a deployment-owned identity resolver:

```powershell
router-dump-server --plugin-deployment-module deployment.plugins:build `
  --state-dir .\.runtime\control-plane `
  --identity-resolver-module deployment.identity:resolve_control_plane_identity `
  --private-analysis-deployment-module deployment.private_analysis:build `
  --host 0.0.0.0 --port 8765
```

Choose exactly one plug-in source: repeat `--plugin` for ordinary installed
candidates, repeat `--plugin-module PACKAGE[:ATTRIBUTE]` during source
development, or use one mutually exclusive
`--plugin-deployment-module PACKAGE:ATTRIBUTE` trusted descriptor. The
descriptor binds the complete primary registry, auxiliary-provider directory,
and immutable composition policy as one content-addressed deployment. This server
serves aggregate root `/health` and `/v1/control-plane`: it accepts no startup
dump and mounts no startup single-node analyzer routes, frontend, or assets.
Its scoped `.../analysis/query` API still supports durable inspection without
a startup dump. To use `/manage` with this API-only server, serve the frontend
through the [documented same-origin development proxy](frontend/README.md#develop-the-frontend-separately)
or an authenticated deployment-owned frontend host; the server itself does not
serve browser pages. Its
configured instances remain distinct through probing, manual selection,
restart, publication, and capability routing by their paired `instance_id` and
`registered_execution_identity`.

The descriptor is strict by default. A trusted, single-host embedding whose
registry intentionally uses `allow_manifest_identity=True` may opt the complete
durable deployment into synchronous inline execution at the descriptor call
site:

```python
from router_dump_analyzer import PluginCompositionDeployment

return PluginCompositionDeployment(
    primary_registry,
    capability_providers,
    composition_policy,
    allow_inline_only=True,
)
```

That option is deployment-owned Python authority; no upload, HTTP request, or
command-line input can enable it. It admits registry-created `inline_only`
records, including the manifest-identity fallback, and forces the whole primary
ingestion pipeline inline if any primary or retained provider record requires
it. Even an otherwise unused provider kept for historical plans therefore
selects inline execution. The default constructor remains PROCESS-only.

Private-analysis lifecycle routes remain inert when the optional deployment
module is omitted. The `PACKAGE:ATTRIBUTE` target is process-trusted local
Python: it must return a frozen `PrivateAnalysisDeployment`, or be a factory
called once with a frozen context containing only the canonical state
directory. It registers approved in-process or shell-free local-subprocess
runners. Each runner selects exactly one evidence mode: a deployment-owned
spawned request-bound service factory, an explicitly unbounded trusted-inline
compatibility factory, or the core's immutable indexed corpus for the exact
requested revision set. The spawned form is the bounded production custom
mode; it accepts only a module-level target and canonical configuration, never
a live pickled callable. An in-process runner retains a detached clone and a
bounded seal of its exact callback code, imports, closures, executable state,
and callable class/instance state; it revalidates that seal immediately before
invocation. A local-subprocess runner instead seals its actual executable and
ordered helper artifacts by canonical path, metadata, and bytes. Every argv
file operand must be an attested helper or an explicitly classified runtime-data
argument, and the classification is rechecked immediately before shell-free
launch; `-c` and `-m` dynamic-code forms are ineligible. Runtime-data arguments
must never identify or load executable code. The latter core mode can expose
client-safe projections, or full-fidelity proprietary normalized records only
when both workspace policy
and runner policy explicitly allow it. This is not a device plug-in, a public
model API, or a sandbox. The analyzer entry point accepts the same option only together
with `--control-plane-dir`. OpenAPI, Swagger UI,
and ReDoc are disabled by default. `--expose-api-docs` enables them only on a
loopback listener; a non-loopback configuration is rejected. The resolver
target must be a synchronous module-level
callable that verifies credentials and returns a `ControlPlaneIdentity`. For
loopback development only, replace the resolver option with
`--trust-control-plane-headers`; the trusted-header adapter cannot be enabled
on a non-loopback listener. That adapter grants exactly the read, write, and
tenant-admin roles by default. Add `--grant-instance-operator` only when a
loopback development process must also grant the independent
`control-plane:instance-operator` role; the flag controls the role grant, not
one particular endpoint. It is rejected with a custom resolver or a
non-loopback listener.
The two health routes intentionally require no tenant identity and return only
bounded aggregate serving/queue/telemetry status; they never expose scope IDs,
paths, event fields, credentials, or exception text.
The separate operational-diagnostics route is authenticated, requires the
exact `control-plane:instance-operator` role, and sets `Cache-Control: no-store`.
A tenant `control-plane:admin` does not imply this instance-wide role. The
response is deliberately hybrid: `operational_events` is process-global, while
`access_denial_sampling` covers all tenants observed by the installed ASGI app.
It is an advisory troubleshooting snapshot, not a durable audit or compliance
record, and resets when the process restarts.

Durable ingestion also freezes the plug-in composition policy used for every
import. The primary parser still comes from probe/selection. A
content-addressed deployment rule may attach exact auxiliary capability
providers and roles to that exact primary executable identity; registration
order and matching names never select them. The policy digest is stored with
the queued import and in the current v4 execution plan; a worker refuses to
continue if deployment composition has changed. Process workers also
live-revalidate selected auxiliaries after the child returns and before its
plan can be staged, so executable or manifest drift during parsing fails the
import. An unfinished pre-contract import is migrated only by clearing its old
candidates/selection and binding the explicitly active policy before re-probe;
staged and completed history is never rewritten. Even an unrelated policy edit
therefore changes the durable revision/session/private-analysis identity.
Retained plan-v1 rows stay readable but cannot route or produce private
evidence. Retained plan-v2 rows remain executable but decode their previously
unrecorded execution authority as `legacy_unrecorded`; retained plan-v3 rows
record the weakest whole-plan authority. New plan-v4 PROCESS pins additionally
commit to the exact inert child bootstrap before any target is imported;
trusted-inline v4 pins carry `null` because they have no subprocess authority.
This lets one topology contain different
platforms, firmware, and chip-specific helpers without merging their authority.
`ControlPlane.capability_router_for_revision()` and
`capability_router_for_revision_set()` are the production consumers: they load
the retained plan, preserve session or snapshot member IDs, and resolve only
the exact configured providers from that deployment. They never substitute a
newly installed provider for a stale or missing pin.

For CI or another frontend-free workflow, use the same durable lifecycle
without starting HTTP or ingestion:

```powershell
router-dump-private-analysis --plugin-deployment-module deployment.plugins:build `
  --state-dir .\.runtime\control-plane `
  --tenant example-tenant --project lab-project --workspace regression-2026-07 `
  --private-analysis-deployment-module deployment.private_analysis:build `
  --output .\artifacts\private-analysis-report.json --pretty `
  run --request .\private-analysis-request.json `
  --actor ci-review --idempotency-key build-1042
```

The strict, at-most-1-MiB UTF-8 request file uses the same caller-intent object
as HTTP: revision IDs, public runner ID/version, task kind, query, clock, and
optional limits. The proprietary query is file-only and never a command-line
argument. `runners`, `create`, `get`, `list`, `execute`, `cancel`, `report`,
`recover-expired`, `decide-proposal`, `list-decisions`, `get-decision`,
`recover-decision`, and the create-execute-report convenience command `run`
are available. The command opens the existing tenant/project/workspace and
disclosure policy; it
does not create scope, start workers or a server, retry a failed runner,
switch transports, or automatically promote a proposal. Promotion requires a
separate human-authored decision file and the explicit `decide-proposal`
command; recovery requires an explicit `recover-decision`. It writes bounded
JSON (`router_dump_analyzer.private_analysis_cli_result.v1`) to stdout and,
optionally, `--output`. Exit `0` means success, `2` means `run` reached a
terminal advisory error rather than a model result, and `1` means command or
service failure.

`recover-expired --actor ACTOR [--limit N]` is the no-retry crash-recovery
operation. It affects only the selected tenant/project/workspace and returns
the runs it terminalized. It never invokes the model; attempts protected by an
unowned cleanup fence remain pending because a restarted process cannot prove
the original child was reaped.

Core contains no public-model SDK, endpoint, API-key setting, network
transport, arbitrary-shell command, or automatic fallback. The adapter from a
locally approved model to the runner contract remains deployment-owned and
should be protected with the deployment's own process/network controls.

To mount the same control-plane routes beside one browser analysis, add
`--control-plane-dir .\.runtime\control-plane` to `router-dump-analyzer`; the
routes then appear under `/v1/control-plane`. Add
`--private-analysis-deployment-module PACKAGE:ATTRIBUTE` only when that
embedded control plane should load the same explicitly trusted local runner
composition; the option is rejected without `--control-plane-dir`.
On the default loopback listener this explicitly installs the local
trusted-header development adapter. A non-loopback listener is rejected unless
the unsafe development override is supplied; production ASGI hosting must
install a resolver backed by verified credentials.
The local adapter allowlists the exact listener host and mutation origin. It
is safe against local DNS rebinding but still is not authentication; for local
development it explicitly grants read, write, and tenant-admin roles, with no
instance-operator role by default. The loopback-only
`--grant-instance-operator` option adds that role explicitly.
Resolver-supplied headers on `401`/`403` responses are
accepted only as one atomically validated, bounded safe header map. An invalid
map is dropped in full, becomes a bounded `500` with no resolver-supplied
headers, records the original typed denial with the actual response status
`500`, and emits the separate payload-free
`control_plane.identity_resolver.response_headers_rejected` event.
`Set-Cookie` and obsolete `Set-Cookie2` are always rejected: cookie mutation
belongs in authenticated upstream middleware or a dedicated endpoint, not an
identity resolver. A future exception requires a typed cookie policy rather
than a generic header allowlist.
Fixture admission and revision publication are independently staged before
their catalog calls. Recovery replays either exact operation idempotently; a
lost publication response does not run the plug-in a second time. Catalog
calls have their own deadline and, in the production-default `process` mode,
run in a disposable spawned child. A publisher that ignores its context is
terminated, killed if necessary, and reaped at the deadline. The built-in
SQLite catalog reopens its durable database in that child and also bounds lock
and database waits cooperatively. An ambiguous timeout keeps the exact outbox
retryable, pins its artifact, and degrades health immediately until it is
reconciled. Core never pickles a live custom publisher. Process mode rebuilds
it from an explicit module-level `publisher_module_target`, or from an
importable no-argument class; stateful/configured publishers must use the
explicit target. Trusted embeddings may explicitly select synchronous
publisher `inline` mode, which has no enforced-cancellation claim. The browser
follows bounded catalog/review pages, honors the context's `can_write` result,
and reconciles ambiguous marker/correlation responses by stable client record
and operation IDs. Annotation pages are bound to one audit watermark; one
concurrent-change restart is allowed, after which the last confirmed
same-scope marker view remains visible.
Plug-in registries fingerprint the complete bounded import scope and fail
closed by default when no executable identity can be derived. Packages use
`package-sha256:`. When any PEP 420 namespace precedes the defining module,
every search location of the first namespace ancestor participates in
import-precedence order, even if the plug-in later enters a regular subpackage.
A genuine top-level
module uses the distinct `module-sha256:` identity instead of being mislabeled
as a one-file package. Sourceless `.pyc`/`.pyo` modules fail closed because
embedded build paths are not relocation-stable; their loader must supply an
immutable artifact digest. Registry-derived identities are recalculated immediately
before plug-in execution. The manifest-only
compatibility fallback is available only to an explicitly opted-in local/test
registry (`allow_manifest_identity=True`). It cannot back PROCESS execution,
but an explicitly trusted deployment may admit it with
`PluginCompositionDeployment(..., allow_inline_only=True)`.
If package bytes can still be derived but a stateful process target cannot be
attested, that non-strict registry records the exact package identity as
`inline_only`: trusted inline capability use remains available with package
revalidation. Process workers still reject the registration; durable
publication accepts it only through the same explicit trusted-inline deployment
mode. Explicit loader-supplied hashes and strict registries never take this
fallback.
By default, the durable servers and `router-dump-ingest` run plug-in probe and
parsing in spawned child processes with a bounded deadline (300 seconds by
default).
Timeouts are killed and reaped, become durable import failures, and never
publish a partial dataset. Core sends only an inert scalar/tuple bootstrap,
then reloads module-level targets or invokes importable no-argument constructors
inside the child. It never pickles live plug-ins, registries, coordinators,
decoders, providers, or bound methods. Configured/stateful components use
explicit process module targets. A non-default programmatic configuration
digest requires an explicit module-instance plug-in target, with corresponding
targets for asserted custom coordinator/decoder state; installed/direct-module
loaders provide their target automatically. A live entry-point instance that
adds only parent-side runtime integration may declare an exact immutable
`PluginProcessBootstrapDescriptor` on its concrete class, naming the same live
instance or its exact no-argument class as the separately attested child target.
The declaration carries no configuration and does not relax the configured
state rule. The child must reproduce the frozen
execution identity. That identity includes every non-recursive loader target,
each target's source-backed module/package and Python-code identity, loader
mode, package-verification choice, and frozen ingestion/artifact limit used by
the child, so a target-only or target-file change cannot retain the same plan
authority. Target bytes are checked before spawn, in the child, after child
return, and before final revision staging. Dynamic aliases and sourceless
targets fail closed. This protects the control-plane process from a hung or
crashed plug-in; it does not remove the plug-in's filesystem, network, or
host-user access. Programmatic embeddings may explicitly choose synchronous
`inline` execution for trusted local/tests, but it has no timeout or
bounded-cancellation claim; process mode is the only killable boundary. Trusted
inline durable deployment also forfeits subprocess crash, CPU, and memory
containment; `close()` may stall or fail; the same live object and mutable state
may be shared across jobs, tenants, and concurrent workers; and the plug-in has
the embedding process's ambient host access. Every tenant and operator sharing
that instance must trust it. Make the plug-in thread-safe or configure one
worker (`max_workers=1`). The durable publisher remains PROCESS by default
unless the embedding explicitly overrides that separate mode.
Across validator descriptors/hooks, capability execution, registry probing,
trusted inline ingestion, installed loading, runtime/session providers, and
normalized temporal/topology/route callbacks, the core boundary policy rethrows
`KeyboardInterrupt`, `SystemExit`, and `GeneratorExit` unchanged and contains
every other `BaseException` behind bounded fixed public diagnostics. It
snapshots executable descriptors once and contains lazy iteration, cleanup,
and context entry/exit as part of the call. Plug-ins
must use structured `PluginDiagnostic` values rather than exception text for
author-visible detail.
The default analyzer CLI enters its real application lifespan before Uvicorn
starts, so an ordinary plug-in startup failure exits 1 with one bounded,
path-free error line instead of a server traceback. Process-control exceptions
remain unchanged.

Client-visible failures use closed safe code/message pairs; arbitrary plug-in
exception text stays in private diagnostics with no HTTP route.

Retention is disabled by default. A versioned JSON policy can enforce logical
tenant/workspace byte and import-count quotas even while deletion stays off.
Preview one workspace without starting workers:

```powershell
router-dump-maintain `
  --state-dir .\.runtime\control-plane `
  --tenant example-tenant `
  --project lab-project `
  --workspace regression-2026-07 `
  --policy .\retention-policy.json `
  --output .\artifacts\retention-preview.json `
  --pretty
```

The preview is deliberately lock-free and does not walk host orphan storage;
its ingestion result says
`host_storage_orphan_inventory="not_observed"`. Destructive execution performs
the existing bounded host scan and reports `"bounded_host_scan"`, so zero
preview counts cannot be mistaken for complete host coverage.

For a read-only CI or operator check that does not load a plug-in or analysis
session:

```powershell
router-dump-health --state-dir .\.runtime\control-plane --pretty
```

It reports pending, user-selection, and stalled queue counts. Exit `0` is
healthy, `2` is degraded, and `1` means the state could not be inspected.

Destructive maintenance additionally requires `--execute`, `--actor`, and a
stable `--operation-id`; the HTTP equivalent requires the separate admin role
and `Idempotency-Key`. Catalog, review, and ingestion journals make exact
replay crash-resumable while rejecting changed actor, policy, or clock inputs
before mutation. See the
[retention guide](docs/control-plane.md#7-retention-quotas-and-maintenance)
for the policy example and safeguards.
The explicit destructive host pass also reclaims only exact, stale
core-generated blob/dataset `.partial` and `.corrupt-...` crash artifacts under
activity/install locks; live publications and arbitrary dotfiles are preserved.
Anonymous programmatic runs resume any older same-scope pending cleanup journal
before creating another plan.

Core also emits bounded best-effort operational events through the standard
Python logger `router_dump_analyzer.operations`. Records use schema
`rda.operational.v1` and cover ingestion catalog calls and failures, worker
failure/exit signals, retention planning/truncation, cleanup batches, replay,
completion, and centrally translated control-plane access denials.
Invalid identity-resolver header maps additionally emit the zero-field
`control_plane.identity_resolver.response_headers_rejected` class.
The fixed-capacity handoff never blocks ingestion or retention and may drop
telemetry; durable queue, outbox, cleanup-progress, and audit rows remain the
source of truth. Both health routes publish aggregate accepted, dropped,
delivery-failure, queue-depth/capacity, and logging-worker-liveness counters;
any observed loss degrades health without exposing event payloads. Events never
include dump content, filesystem paths, raw tenant/identity/header values, or
exception text. Access-denial events use closed phase/reason/route fields,
geometric/time coalescing, permanent admitted-key state, a permanent overflow
bucket after the key bound is full, and an independent global token-bucket
admission ceiling. New keys cannot reset first-occurrence eligibility through
eviction. An optional process-random HMAC token is derived only from the
trusted resolved tenant and is emitted only when bounded candidate state
proves that tenant is a strict majority of the sampled window; uncertainty
omits the token. Phase and reason are exact closed enums and are revalidated at
the reporter and operational-record boundaries. Intentional sampling, global
admission suppression, overflow observations, and real enqueue loss have
separate process-local counters. Anonymous health keeps its aggregate-only
schema; the protected diagnostics endpoint exposes the payload-free per-event
and sampling breakdown. Its queue counters are process-global; its denial
sampler is scoped to the installed ASGI app and aggregates that app's tenants.
A deployment configures handlers, formatting, and export through ordinary
Python logging rather than a plug-in hook.

Integer-bearing API inputs use an explicit domain rather than inheriting one
generic bound. Nanosecond instants use signed 64-bit bounds and are normally
returned as decimal strings. Browser-visible numeric paging offsets are
limited to `0..9007199254740991` (`2^53-1`), with smaller route-specific caps
where declared; `2^53` is rejected instead of being echoed imprecisely.
Caller-supplied audit cursors and watermark preconditions use canonical
non-negative ASCII decimal syntax and the range `0..9007199254740991`. This
includes retention `audit_before_sequence`, annotation
`expected_audit_watermark`, review-audit `after_sequence`, and both retention
journal cursors. Stored and projected audit sequences use the same exact
integer range. Writes that would exhaust it and reads that encounter an
out-of-domain stored value fail closed.
The [durable control-plane guide](docs/control-plane.md) documents the exact
state machine, route table, optimistic concurrency, idempotency, recovery,
security boundary, and core-versus-plug-in ownership.

## Developer workflows

### Typed Python API

All shipped Python import roots carry PEP 561 metadata and module-for-module
stubs: the core `router_dump_analyzer` package, the demo's
`rsl_demo_plugin` and `rsl_demo_generator` packages, and the independent
`state_dump_generator` package. An IDE or type checker therefore sees the
public classes, protocols, functions, constants, and aliases after an ordinary
wheel or editable install; consumers do not need a separate `types-*` package.
The `.pyi` files describe the Python surface, while the executable code and the
normative contracts remain authoritative for runtime validation and behavior.

The repository keeps one stub beside every Python module and a `py.typed`
marker in every package root. Run both drift and consumer checks after changing
an exported signature:

```powershell
python -m pip install -e ".[test,web]" -e .\demo -e .\state-dump-generator
python scripts/export_type_stubs.py --check
python -m mypy --python-version 3.12 --strict --no-incremental tests/typing/public_api.py state-dump-generator/tests/typing/generator_public_api.py
```

To refresh an intentional API change, run
`python scripts/export_type_stubs.py`, review the generated signatures, then
repeat the two checks above. Plug-in authors can type-check their own package
against the installed core with the same Python 3.12 strict-mypy settings.

The typed cross-node topology surface is exported the same way. The public
core facade includes the frozen federation executor and coordinator models;
plug-in-owned claim, match-policy, and linker protocols remain in
`router_dump_analyzer.plugin_api`.

### Run the checks

With `router-dump-analyzer-demo` activated:

```powershell
python -m pip install -e .\state-dump-generator
python scripts/run_topology_federation_gate.py
python -m ruff check --select E9,F63,F7,F82 src demo state-dump-generator/src tests demo/tests state-dump-generator/tests
python -m mypy --python-version 3.12 --ignore-missing-imports --check-untyped-defs src/router_dump_analyzer/canonical.py src/router_dump_analyzer/route_trace_core.py src/router_dump_analyzer/topology_core.py
python -m unittest discover -s tests -v
python -m unittest discover -s demo/tests -v
python -m unittest discover -s state-dump-generator/tests -v
npm --prefix frontend run check
```

`run_topology_federation_gate.py` is the short executable pass gate for the
complete connector-claim path. It must end with
`PASS: typed topology federation gate`. Its nine fail-fast phases prove:

1. the declared plug-in contract, maintained author-document consistency,
   exact validation, detached outputs and authority-bearing requests,
   steering-intent isolation, and independent record/claim budgets;
2. immutable heterogeneous provider routing, exact-token and allowlisted-linker
   federation, interval-bound temporal and ambiguity handling, and directed,
   presentation-safe route matching;
3. the browser-facing generated topology API, including incomplete and
   single-member claim coverage;
4. generated typed route HTTP integration, including full-window temporal
   filtering, strict and best-effort unknown-status behavior, exact/linker
   ownership, and every incomplete or truncated fail-closed path;
5. local-only identity compatibility without PROCESS authority, including the
   explicit trusted-inline durable deployment boundary, plus the real demo's
   live-runtime/PROCESS-safe class-bootstrap split;
6. checked-in `.pyi` drift detection;
7. runtime/stub structural parity, including generated dataclass constructors;
8. strict type checking of downstream public-API consumers; and
9. executable frontend manifest, syntax, and JavaScript behavior tests.

Every phase runs in a fresh bytecode-cache directory with a 300-second
wall-clock timeout. Timeout cleanup terminates that phase's process tree, so a
failed check does not leave test workers behind. A missing Node/npm runtime,
timeout, non-zero phase, stale stub, typing error, or frontend contract failure
is a failed gate. The complete core, demo, generator, and frontend suites
listed above remain the release gate.

The frontend check requires Node.js 18 or newer but installs no packages. CI
runs the same gates on Windows and Linux with Python 3.12 and Node 22. A second
Windows/Linux Python matrix constrains Uvicorn to the declared 0.30.0 floor,
asserts that exact resolution, runs `pip check`, and repeats the complete core
and demo suites. The normal matrix exercises the current compatible resolver
result. An additional Linux job syntax-checks the shell launchers, builds all
three distributions through their source archives, installs the wheels
together, and verifies their entry points and packaged resources.

### Develop frontend and backend separately

The normal launcher uses one process. For split-process frontend work, start the
API:

```powershell
.\scripts\launch_demo.cmd -ApiOnly -NoBrowser
```

In another terminal:

```powershell
npm --prefix frontend run check
npm --prefix frontend run serve
```

Open `http://127.0.0.1:4173`. The development server proxies API and
documentation requests to `http://127.0.0.1:8765`. See the
[frontend guide](frontend/README.md) for details.

If the backend uses a nondefault port, tell the frontend server explicitly:

```powershell
npm --prefix frontend run serve -- --backend http://127.0.0.1:8876 --port 4174
```

### Regenerate fixtures

The launcher creates a missing assembly and safely replaces an exact
generator-owned archive when it is no longer the complete full-scale ten-node
corpus, its recorded authoring-source digest no longer matches
`demo/router-state-lab-default.scenario.json`, or its materializer fingerprint
no longer matches the loaded generator and demo plug-in implementation.
Unknown preferred inputs remain
untouched and use the fixed `.generated.tgz` recovery sibling; an unknown
recovery path fails closed. The `-RebuildFixture` and `--rebuild-fixture`
examples above cover forced regeneration. Maintainers can use the canonical
direct generator, verification, and development-corpus commands in the
[sample-input guide](samples/README.md#generate).
That guide also owns the assembly layout and deterministic-generation behavior;
the demo guide owns the current projection and evidence contract.

## Project map

| Path | Contents |
|---|---|
| [`src/router_dump_analyzer/`](src/router_dump_analyzer) | Protocol-neutral core contracts and engines, the only CLI/FastAPI application and routes, runtime lifecycle, plug-in loaders, and frontend host |
| [`docs/control-plane.md`](docs/control-plane.md) | Durable catalog, queue, sessions, review overlay, reports, HTTP/CLI use, and operational boundary |
| [`demo/rsl_demo_plugin/`](demo/rsl_demo_plugin) | The standalone example plug-ins: one primary parser plus one separately identified private-evidence auxiliary, their exact deployment policy, presentation policy, non-web fixture input/session providers, and topology/route fixture policy; no executable or web application |
| [`demo/router-state-lab-default.scenario.json`](demo/router-state-lab-default.scenario.json) | Canonical human-authored scenario save consumed by future demo generations |
| [`demo/rsl_demo_generator/`](demo/rsl_demo_generator) | The separate standard-library scenario adapter and scalable mock-dump materializer, with an explicit one-way dependency on the example plug-in's declared fixture semantics |
| [`frontend/`](frontend) | Core-owned HTML pages, JavaScript, CSS, page manifest, and dependency-free checks |
| [`state-dump-generator/`](state-dump-generator) | Independent GNS2-style scenario editor and topology-free per-node dump generator |
| [`demo/fixtures/`](demo/fixtures) | Small parser/runtime-v2 conformance fixtures; the full mock dumps remain generator-owned and runtime-v1 compatible |
| [`samples/`](samples) | Public decoder inputs and fixture documentation |
| [`scripts/`](scripts) | Environment setup, launchers, the public-type-stub exporter, and the optional public CTF decoder-fixture fetcher |
| [`tests/`](tests) | Backend, API, fixture, scale, and frontend regression coverage |
| [`docs/`](docs) | Architecture, contracts, authoring guidance, and audit records |

## Documentation

| Document | Use it for |
|---|---|
| [Architecture and library decisions](docs/architecture.md) | System boundaries, temporal model, reconstruction, performance, and security |
| [Private AI analysis boundary](docs/private-ai-analysis.md) | Local-only model transport, default-deny workspace disclosure policy, full-fidelity private evidence, advisory provenance, and explicit human proposal-review rules |
| [Durable control plane](docs/control-plane.md) | Local durable ingestion, catalogs, sessions, annotations, reports, routes, and operations |
| [API payload contract](docs/api-contract.md) | External state, topology, history, timeline, correlation, and route APIs |
| [Plug-in author quickstart](docs/plugin-author-quickstart.md) | A linear, copy-paste path to a first plug-in |
| [Plug-in contract and lifecycle](docs/plugin-contract.md) | Normative hooks, identity, provenance, topology, routes, and conformance |
| [Public sample-input catalog](docs/public-sample-catalog.md) | Open-source traces and other useful test inputs |
| [Comprehensive audit — 2026-07-26](docs/comprehensive-audit-2026-07-26.md) | Security, correctness, ownership remediation, validation, and deferred structural work |
| [Sample input guide](samples/README.md) | Synthetic fixture contents and generation |
| [Frontend guide](frontend/README.md) | Browser/backend boundary and split-process development |

## Current scope

Router State Lab is an implementation-oriented design package, deterministic
conformance corpus, interactive review demo, and durable single-host ingestion
profile. Core-owned runtime v2 safely inventories and normalizes a local file,
directory, tar, or ZIP through a standard parser plug-in. The optional control
plane adds bounded raw-body uploads, deterministic multi-plug-in probing and
selection, content-addressed artifacts, a transactional SQLite queue,
tenant/project/workspace catalogs, immutable fixture/revision publication,
crash-recoverable fixture-admission and revision-publication outboxes,
multi-revision sessions and snapshots,
an audited mutable review overlay, admission quotas, and bounded audited
single-host retention.

That is not a claim of a complete multi-host service. Built-in CTF decoding,
hardened plug-in sandboxes/containers with OS resource and network controls,
credential authentication, TLS, distributed databases/object storage/queues,
full telemetry export/alerting, distributed retention, and backup remain
deployment or future work. The shipped durable profile does provide a bounded
non-blocking operational event channel and killable, deadline-bounded
child processes for plug-in probe and parsing, but they run as the host user
and are not a security sandbox. The HTTP boundary can enforce roles and
project/workspace scopes returned by a host identity resolver; the CLI's
loopback adapter merely trusts headers. Runtime-v2 temporal/topology/route
providers are also not yet supplied. Scoped relationship-collection
completeness is retained during ingestion but not yet materialized into public
relationship interval/query semantics.

The standard ingestion path retains events but does not automatically run
reducer/reversion or event-correlation hooks. Those require an explicitly
configured host; durable publication does automatically schedule selected
revision relationship projectors, followed by consistency checks. See the
[capability support matrix](docs/plugin-contract.md#2-capability-boundary).
