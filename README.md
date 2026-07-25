# Router State Lab

**Explore how router state changes across time, layers, and devices.**

Router State Lab is a runnable design and conformance demo for a temporal router
dump analyzer. It turns heterogeneous status tables and logs into resources,
events, relationships, topology, and route explanations that can be inspected at
any point in a capture. The protocol-neutral analyzer core is packaged
separately from the demo server, synthetic demo plug-ins, and browser
application.

The repository includes a deterministic **125,000-event / 10,000-resource**
scenario covering IS-IS, SR-MPLS, SRv6, EVPN multihoming, MPLS VPNs, failover,
and cross-layer inconsistency.

> [!IMPORTANT]
> The web application currently reviews the bundled synthetic dump. It does not
> yet accept arbitrary uploads or act as a production plug-in coordinator.

## Start here

| Goal | Go to |
|---|---|
| Run the bundled demo | [Run the demo](#run-the-demo) |
| Learn what to inspect | [What to try](#what-to-try) |
| Build a device plug-in | [Plug-in author quickstart](docs/plugin-author-quickstart.md) |
| Integrate with the API | [API payload contract](docs/api-contract.md) |
| Understand the design | [Architecture and library decisions](docs/architecture.md) |
| Regenerate sample data | [Sample input guide](samples/README.md) |

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
installing the core alone does not install FastAPI, Uvicorn, demo plug-ins, or
browser assets. The launcher generates the deterministic packed fixture when
it is missing, starts the server, and opens `http://127.0.0.1:8765`.

If port 8765 is occupied:

```powershell
.\scripts\launch_demo.cmd -Port 8876 -NoBrowser
```

To rebuild the complete fixture:

```powershell
.\scripts\launch_demo.cmd -RebuildFixture -NoBrowser
```

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
5. **Inspect scale without losing detail.** Browse the virtualized 125K-event
   log, zoom-aware density lane, 10K-resource tables, unmatched-log lanes, route
   tables, neighbor data, and plug-in-defined dashboards.
6. **Look for disagreement.** Review delayed or failed updates, changing next
   hops, asymmetric forwarding, and differences between control-plane,
   forwarding, and hardware-layer reachability.

Topology and route-path graphs support node dragging, background panning,
touchpad gestures, pinch zoom, and Ctrl-wheel zoom. Hover or keyboard-focus
interactive elements for provenance, status, resolution, and inference details.

## The bundled scenario

One outer TGZ contains four synthetic container dumps. Each container includes
synthetic CTF 2 streams and resource-status text; some contain one table and
others contain several typed tables. This archive drives the 125K-event
single-node workspace. The topology and route pages use a separate built-in
multi-node provider; their underlay and route facts are not decoded from the
packed dump.

| Dimension | Included coverage |
|---|---|
| Scale dump | 125,000 matched events, 10,000 resources, 47,598 relationship intervals, and 58,198 relationship mutations |
| Protocols | Connected and static routes, IPv4/IPv6 unicast, IS-IS, SR-MPLS, SRv6, MPLS transport/L3VPN, and EVPN types 2 and 5 |
| Multi-node route model | Ten assembly members (nine selected by default and one intentionally unavailable), seven routed nodes, shared and external subnets, VLAN subinterfaces, LAGs, physical ports, and EVPN Ethernet Segments |
| Resource history | Forwarding Groups, ETGs with ETE paths, standalone DTEs, Virtual Interfaces, Glue, neighbors, IP routing, and hardware objects |
| Change waves | Single-home creation, multihome expansion, mass ES withdrawal and failover, mass restore, and distinct next-hop churn |
| Failure cases | Recursive and cross-node loops, split-horizon policy exclusion, hop/recursion limits, dead candidates, stale FIB state, cross-layer mismatch, missing intermediate resolution, one-way forwarding, and clock uncertainty |

The core also exposes a protocol-neutral, unit-tested packet-evolution IR for
ordered opaque layers, exact before/after continuity, exact-basis MTU checks,
bounded steps, and counterfactual user steering. Eight advanced route scenarios
now pass demo-plug-in packet declarations through those core evaluators and
show native IP, SR-MPLS/PHP, L3VPN labels, SRv6, IP-in-IP, nested VPN, MTU
failure, and forced steering in the route view. This is still a demo-provider
integration, not a production coordinator that discovers and invokes the
trace-time hook at every installed node.

The full corpus is indexed by default. Timeline, graph, event-log, and table
queries are bounded or virtualized rather than sending the entire dataset to the
browser. A content- and projection-keyed SQLite sidecar caches only client-safe
derived search text; raw and plug-in-declared sensitive values are not indexed.

The Linux/WSL launcher also exposes the smaller embedded projection for an
intentional lightweight UI review:

```bash
./scripts/launch_demo.sh --review-projection
```

## How the design is divided

The central rule is simple: the core owns generic temporal machinery; plug-ins
own device and protocol meaning.

| Owner | Responsibilities |
|---|---|
| Core | Immutable revisions, safe archive inventory, source records, generic temporal storage, uncertainty, bounded queries, pagination, API contracts, LPM, bounded recursive/multipath traversal, exact packet-state continuity and MTU arithmetic over matching declared bases, immutable flow direction, exact endpoint-goal and typed-policy comparison, bidirectional aggregation, cycle/limit handling, and reusable UI components |
| Device plug-ins | Dump recognition, input parsing, resource types and keys, state transitions, relationships, forwarding-object projection, candidate rank/group semantics, packet-layer/action/overhead and disposition semantics, typed policy scopes, endpoint attachments and local terminal classification, topology classifications, consistency rules, route-resolution text, icons, and dashboard descriptors |
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
- **Copy:** [Minimal installable plug-in](examples/minimal_plugin)
- **Reference:** [Normative plug-in contract](docs/plugin-contract.md)

After running the normal environment setup, validate the example:

```powershell
conda activate router-dump-analyzer-demo
python -m pip install --no-deps -e examples/minimal_plugin
router-dump-plugin-validate minimal_router `
  --artifact examples/minimal_plugin/fixtures/minimal-status.jsonl `
  --node-hint router-1 `
  --metadata platform=minimal-router-os `
  --metadata software_version=1
python -m unittest discover -s examples/minimal_plugin/tests -v
```

The validator checks discovery, manifest compatibility, schemas, capabilities,
hooks, and parser selection. It intentionally does not execute the parser; the
example's golden test verifies the device-specific output.

## Developer workflows

### Run the checks

With `router-dump-analyzer-demo` activated:

```powershell
python -m unittest discover -s tests -v
npm --prefix demo/frontend run check
```

The frontend check requires Node.js 18 or newer but installs no packages.

### Develop frontend and backend separately

The normal launcher uses one process. For split-process frontend work, start the
API:

```powershell
.\scripts\launch_demo.cmd -ApiOnly -NoBrowser
```

In another terminal:

```powershell
npm --prefix demo/frontend run check
npm --prefix demo/frontend run serve
```

Open `http://127.0.0.1:4173`. The development server proxies API and
documentation requests to `http://127.0.0.1:8765`. See the
[frontend guide](demo/frontend/README.md) for details.

### Regenerate fixtures

The launcher automatically creates missing fixtures. Maintainers can regenerate
them directly:

```powershell
python scripts/generate_sample_bundle.py
python scripts/generate_scale_fixtures.py --events 125000 --resources 10000
python scripts/generate_packed_scale_bundle.py
```

The generators are deterministic, and generated scale data is not checked into
source control. See the [sample input guide](samples/README.md) for the fixture
layout, public CTF source, and scenario phases.

## Project map

| Path | Contents |
|---|---|
| [`src/router_dump_analyzer/`](src/router_dump_analyzer) | Protocol-neutral core contracts, validators, query helpers, and route-policy evaluation |
| [`demo/src/router_dump_analyzer_demo/`](demo/src/router_dump_analyzer_demo) | FastAPI demo server, fixture runtime, topology/route scenarios, and frontend host |
| [`demo/src/router_dump_analyzer_demo_plugins/`](demo/src/router_dump_analyzer_demo_plugins) | Synthetic fixture semantics and presentation policy used only by the demo |
| [`demo/frontend/`](demo/frontend) | HTML pages, JavaScript, CSS, page manifest, and dependency-free checks |
| [`examples/minimal_plugin/`](examples/minimal_plugin) | Small installable reference plug-in with a golden fixture and tests |
| [`samples/`](samples) | Public and generated sample inputs |
| [`scripts/`](scripts) | Environment setup, launchers, fixture generators, and validators |
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
| [Sample input guide](samples/README.md) | Synthetic fixture contents and generation |
| [Frontend guide](demo/frontend/README.md) | Browser/backend boundary and split-process development |

## Current scope

Router State Lab is an implementation-oriented design package, deterministic
conformance corpus, and interactive review demo. It is not yet a production
analyzer: arbitrary upload ingestion, isolated worker execution, persistent
multi-user storage, authentication, and deployment hardening remain future
work. The production direction is documented without presenting those
capabilities as already implemented.
