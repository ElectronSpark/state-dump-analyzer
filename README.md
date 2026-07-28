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
node contains a 125,000-event and 7,500-resource scalable baseline plus its
explicit authored history and final resources** and can be opened either as an
individual temporal workspace or as a member of the same multi-node topology
and route trace. The declared coverage includes IS-IS, IP routing, SR-MPLS,
SRv6, EVPN multihoming, MPLS/L2/L3 VPNs, failover, packet evolution, and
cross-layer inconsistency.

> [!IMPORTANT]
> The bundled launchers review the generated synthetic dump. The core command
> can load an installed or directly named runtime-capable plug-in and an input
> path, but it does not yet accept arbitrary uploads or perform production
> multi-plug-in selection.

## Start here

| Goal | Go to |
|---|---|
| Run the bundled demo | [Run the demo](#run-the-demo) |
| Learn what to inspect | [What to try](#what-to-try) |
| Build a device plug-in | [Plug-in author quickstart](docs/plugin-author-quickstart.md) |
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
test suite. It installs the core and demo as separate editable distributions;
the core distribution owns the generic browser assets, while its optional
`web` extra supplies FastAPI and Uvicorn hosting support. The synthetic plug-in
and fixtures remain demo-only. Before every normal launch, a fast outer-archive
check confirms that the input contains the complete canonical full-scale node
set, one checksum-matching generated dump pack per node, the SHA-256 digest of
the canonical authoring save, and the fingerprint of the demo materializer
that interpreted it. A missing archive is generated, while an unsuitable,
source-stale, or materializer-stale generator-owned archive is rebuilt
atomically. An
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

After the assembly exists, the equivalent core-owned command is:

```powershell
router-dump-analyzer --plugin demo_router `
  --input demo/fixtures/router-state-lab-demo.tgz `
  --port 8876 --no-browser
```

For source-tree development, the same loader can address the module directly:

```powershell
python -m router_dump_analyzer `
  --plugin-module rsl_demo_plugin `
  --input demo/fixtures/router-state-lab-demo.tgz `
  --no-browser
```

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
server stays in the foreground until you press `Ctrl+C`.

### Main URLs

| URL | Purpose |
|---|---|
| `http://127.0.0.1:8765/` | Multi-node topology and route tracing |
| `http://127.0.0.1:8765/node` | Individual-node temporal workspace |
| `http://127.0.0.1:8765/docs` | Interactive API documentation |
| `http://127.0.0.1:8765/health` | Server and fixture health |

The topology page is the normal entry point. Select a device or endpoint there
to open its node workspace with the same reconstruction context.

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
3. **Travel through time.** Open a node, click a moment, or drag horizontally
   across the timeline to select a range. The resource state, relationships,
   findings, and normalized event list follow the selected time.
4. **Follow causality.** Expand temporal correlations to see dependencies and
   dependents. Ctrl-click a timeline mark to find its normalized log row; in the
   log, use ordinary click/Ctrl-click/Shift-click/drag selection and
   double-click or **Reveal in timeline** to navigate back. Press **Esc** to
   clear the focused selection, event, moment, or range.
5. **Inspect scale without losing detail.** On any node, browse the virtualized
   125K-plus-event log, zoom-aware density lane, 7.5K-plus-resource tables,
   unmatched-log lanes, route tables, neighbor data, and plug-in-defined
   dashboards. Local inventory rows without a plug-in-declared cross-node
   candidate remain visible but explicitly non-traceable.
6. **Resolve a node-local route.** In the node workspace, choose one of that
   node plug-in's advertised route decisions and basis values. The browser does
   not invent a destination or silently fall back to another node's resolver.
7. **Look for disagreement.** Review delayed or failed updates, changing next
   hops, asymmetric forwarding, and differences between control-plane,
   forwarding, and hardware-layer reachability.

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
125,000-event and 7,500-resource baseline per node; explicit authored events
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
| Scale | 10 node revisions; a 125,000-event and 7,500-resource baseline plus node-local authored rows, with at least 100,000 real state-changing events per node |
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
| Core | The `router-dump-analyzer` executable, plug-in loading, FastAPI routes and lifecycle, frontend hosting, immutable revisions, safe archive inventory, source records, generic temporal storage, uncertainty, bounded queries, pagination, API contracts, collision-safe client publication and redaction, exact connectivity-domain/attachment joins over plug-in-declared keys, LPM, bounded recursive/multipath traversal, exact packet-state continuity and MTU arithmetic over matching declared bases, immutable flow direction, exact endpoint-goal and typed-policy comparison, bidirectional aggregation, cycle/limit handling, and the reusable browser application |
| Device plug-ins | Dump recognition, input parsing, resource types and typed/compound keys, state transitions, relationships, forwarding-object projection, candidate paths and directional decisions, candidate rank/group semantics, connectivity-domain matcher/key meaning, packet-layer/action/overhead and disposition semantics, typed policy scopes, endpoint attachments and local terminal classification, topology classifications, consistency rules, route-resolution text, icons, and dashboard descriptors |
| Federation/linker plug-ins | Matching endpoint and boundary claims between members, preserving or explicitly mapping compatible packet/scope contracts, and explaining inter-node connectivity without assuming every device uses the same plug-in |

The core never turns missing evidence into invented state. If forward history,
clock alignment, or cross-layer evidence is insufficient, the result remains
`unknown`, `ambiguous`, `incomplete`, or explicitly best-effort.

See the [architecture](docs/architecture.md) for the complete ownership model,
temporal algorithms, storage recommendation, security boundary, and delivery
sequence. The [advanced route-trace audit](docs/advanced-route-trace-audit-2026-07-25.md)
records the implemented packet boundary, scenario coverage, and remaining demo
integration work.

## Build a device plug-in

For the shortest working path, use these three resources:

- **Start:** [Plug-in author quickstart](docs/plugin-author-quickstart.md)
- **Copy:** [Demo plug-in teaching slice](demo/README.md)
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
runtime v2. The bundled 125,000-event-per-node archive is precomputed and keeps
its runtime-v1 fixture adapter for compatibility.

For advanced reducers, correlation, consistency, topology, or forwarding,
host-side tests call the root-exported `PluginCapabilityExecutor`. It is the
bounded, schema-validating caller for optional hooks; it does not make the
currently unavailable runtime-v2 temporal, topology, or route providers appear.

The maintained author smoke path is:

```powershell
python -m pip install -e ".[web]"
python -m pip install -e demo
python -X utf8 -m rsl_demo_generator `
  --verify-conformance-fixture demo/fixtures/minimal-status.jsonl
router-dump-plugin-validate demo_router `
  --artifact demo/fixtures/minimal-status.jsonl `
  --node-hint router-1 `
  --metadata platform=demo-router-os `
  --metadata software_version=1
python -m unittest tests.test_artifact_core tests.test_ingestion tests.test_capability_executor -v
python -m unittest discover -s demo/tests -v
python -m unittest discover -s state-dump-generator/tests `
  -p "test_runtime_v2_vectors.py" -v
```

See the [demo guide’s compact corpus section](demo/README.md#compact-runtime-v2-conformance-corpus)
for the separate generate/verify commands and the currently executable subset.

## Developer workflows

### Run the checks

With `router-dump-analyzer-demo` activated:

```powershell
python -m ruff check --select E9,F63,F7,F82 src demo state-dump-generator/src tests demo/tests state-dump-generator/tests
python -m mypy --python-version 3.12 --ignore-missing-imports --check-untyped-defs src/router_dump_analyzer/canonical.py src/router_dump_analyzer/route_trace_core.py src/router_dump_analyzer/topology_core.py
python -m unittest discover -s tests -v
python -m unittest discover -s demo/tests -v
python -m unittest discover -s state-dump-generator/tests -v
npm --prefix frontend run check
```

The frontend check requires Node.js 18 or newer but installs no packages. CI
runs the same gates on Windows and Linux with Python 3.12 and Node 22. An
additional Linux job syntax-checks the shell launchers, builds all three
distributions through their source archives, installs the wheels together,
and verifies their entry points and packaged resources.

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
| [`demo/rsl_demo_plugin/`](demo/rsl_demo_plugin) | The standalone example plug-in: parser and presentation policy, non-web fixture input/session providers, and topology/route fixture policy; no executable or web application |
| [`demo/router-state-lab-default.scenario.json`](demo/router-state-lab-default.scenario.json) | Canonical human-authored scenario save consumed by future demo generations |
| [`demo/rsl_demo_generator/`](demo/rsl_demo_generator) | The separate standard-library scenario adapter and scalable mock-dump materializer, with an explicit one-way dependency on the example plug-in's declared fixture semantics |
| [`frontend/`](frontend) | Core-owned HTML pages, JavaScript, CSS, page manifest, and dependency-free checks |
| [`demo/fixtures/`](demo/fixtures) | Small parser/runtime-v2 conformance fixtures; the full mock dumps remain generator-owned and runtime-v1 compatible |
| [`samples/`](samples) | Public decoder inputs and fixture documentation |
| [`scripts/`](scripts) | Environment setup, launchers, and the optional public CTF decoder-fixture fetcher |
| [`tests/`](tests) | Backend, API, fixture, scale, and frontend regression coverage |
| [`docs/`](docs) | Architecture, contracts, authoring guidance, and audit records |

## Documentation

| Document | Use it for |
|---|---|
| [Architecture and library decisions](docs/architecture.md) | System boundaries, temporal model, reconstruction, performance, and security |
| [API payload contract](docs/api-contract.md) | External state, topology, history, timeline, correlation, and route APIs |
| [Plug-in author quickstart](docs/plugin-author-quickstart.md) | A linear, copy-paste path to a first plug-in |
| [Plug-in contract and lifecycle](docs/plugin-contract.md) | Normative hooks, identity, provenance, topology, routes, and conformance |
| [Public sample-input catalog](docs/public-sample-catalog.md) | Open-source traces and other useful test inputs |
| [Comprehensive audit — 2026-07-26](docs/comprehensive-audit-2026-07-26.md) | Security, correctness, ownership remediation, validation, and deferred structural work |
| [Sample input guide](samples/README.md) | Synthetic fixture contents and generation |
| [Frontend guide](frontend/README.md) | Browser/backend boundary and split-process development |

## Current scope

Router State Lab is an implementation-oriented design package, deterministic
conformance corpus, and interactive review demo. It is not yet a production
analyzer. Core-owned runtime v2 can safely inventory and normalize one local
file, directory, tar, or ZIP through a standard parser plug-in, but arbitrary
upload selection, built-in CTF decoding, isolated worker execution, persistent
multi-user storage, authentication, and deployment hardening remain future
work. Runtime-v2 temporal/topology/route providers are also not yet supplied.
Scoped relationship-collection completeness is retained during ingestion but
not yet materialized into public relationship interval/query semantics.
The production direction is documented without presenting those capabilities
as already implemented.
