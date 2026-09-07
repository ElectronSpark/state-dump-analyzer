# Demo core coverage and validation

The scale demo and the small durable-workflow inputs serve different purposes.
The former remains ten nodes with at least 1,250,000 events per node; the latter
exercise the real ingestion/control-plane APIs without copying millions of rows
into a second catalog. A workflow revision is never presented as the startup
fabric's revision merely because their node names match.

## Completion gates

- [x] Expose scenario descriptions and bounded hop/recursion controls; manually
  select ordinary, loop, split-horizon and packet cases and test low budgets.
- [x] Add MTU below/equal/above-limit, incomparable size-basis and incomplete
  packet-state cases using existing core semantics; manually trace each.
- [x] Provide an explicit loopback workbench launcher using the existing
  composition deployment. Tenant roles remain separate from instance operator;
  the ordinary launcher keeps its current security defaults.
- [x] Generate compact before/after inputs with independently keyed resources,
  real projected correspondence and failing/healthy findings. Import them via
  the core, inspect provenance, revisions and immutable session snapshots.
- [x] Register an explicitly scripted, offline evidence runner, not a model.
  Demonstrate query/read/provider dispatch and citations. Disclosure remains
  disabled until explicitly authorized; no network model APIs are introduced.
- [x] Exercise the affected browser workflows, record outcomes/defects, run
  focused regression tests and the full frontend suite, and check author docs.
- [x] Revalidate the canonical full-scale fixture and leave a working demo.

## Existing coverage to retain

The expanded catalog contains 20 route, twelve packet, four topology and five
temporal cases. Reuse its normal IP, SR-MPLS/PHP, SRv6, VPN nesting, ECMP,
failover, asymmetric/transit-start reachability, loop, split-horizon, historical
attachment and stale-update scenarios rather than building another fabric.
Node views retain resource timelines, resource tables, source/event logs,
relationships, consistency and dashboards. `/manage` retains projects,
workspaces, import queues, revision catalog, sessions, snapshots, bounded
inspection, retention, policy and server status.

The [VPN topology samples](../demo/README.md#vpn-topology-samples) add Blue and
Red MPLS L3VPN domains plus Blue EVPN/VXLAN membership to the same fabric. Their
evidence comes from the authoring save's local resources and PE-E's historical
service changes; physical media and route transport paths remain unchanged.

The [cross-node inconsistency samples](../demo/README.md#cross-node-inconsistency-samples)
compare saved sender/receiver MPLS label and VXLAN VNI observations. They are
configuration-evidence disagreements, not inferred packet loss or a requirement
that forward and return use identical paths.

## Honest boundaries

“Core coverage” means demonstrations of implemented public workflows, not every
possible network combination. A scripted evidence runner does not demonstrate
model quality. Synthetic source records do not demonstrate a real platform's
CTF decoder. Authentication, production model deployment and protocol semantics
remain deployment/plug-in responsibilities. `/manage` does not bind arbitrary
durable revisions to the startup route/topology runtime. Automatic scheduling
of reducer/reversion/event-correlation hooks and runtime-v2 route/topology
providers are not added by this work. Destructive retention is not enabled just
to demonstrate a button.

## Validation record

See [the browser audit and remaining improvements](demo-browser-audit-2026-09-06.md).
Checked boxes require execution evidence, not merely source inspection.

Focused checks include 9 launcher/workbench tests, 4 projection-inspection tests
(6 subtests), 41 packet/core/projection tests (132 subtests), 29 demo author tests,
6 independent generator vectors and 36 reconstruction smoke tests. Plug-in
discovery, validation, fixture conformance, a generated compact corpus and a
real durable CLI import passed. The final packet-budget repair additionally
passed 21 packet/core tests (109 subtests) and two API tests (4 subtests).
These groups overlap; their counts are not a unique combined-suite total.

The final frontend suite passed 265 tests; both frontend audit contract classes
passed 51 Python tests. The last independent outcome review passed 33 vectors
and 22 focused route tests. Generated public stubs were checked across 131
modules. Plug-in-author documentation drift was reviewed and the changed
management relationship boundary is documented in the maintained author set.

The broad nine-module README smoke and broad advanced packet API module reached
their enforced 90-second deadlines and are not claimed as passes. Focused
replacements above completed. The frontend distribution checker passed outside
the sandbox after its Windows realpath read was denied inside the sandbox.

## Reproduce the durable workflow

Use the analyzer's Python 3.12 environment consistently (do not share bytecode
caches between different Python patch versions). These are synthetic inputs,
not a second scale demo and not proprietary router dumps.

```powershell
python -m rsl_demo_generator.workbench --output-dir .runtime/workbench-inputs
python -m router_dump_analyzer.pipeline_cli --plugin-deployment-module rsl_demo_plugin.deployment:build_plugin_deployment --state-dir .runtime/workbench-state --tenant demo-workbench --project core-coverage --workspace workflow --project-label "Core coverage demo" --workspace-label "Before and after review" --input .runtime/workbench-inputs/before/minimal-status.jsonl --input .runtime/workbench-inputs/after/minimal-status.jsonl --node-hint workbench-router --timeout 60 --pretty
.\scripts\launch_demo.cmd -Workbench -ControlPlaneDir .runtime/workbench-state -NoBrowser
```

The generator is repeatable and refuses conflicting existing files. The ingest
command replays identical inputs, options and deployment identity idempotently;
changed plug-in/deployment identity creates a new admission. Always inspect the
returned IDs. The `peer` input can be
imported separately with `--node-hint workbench-peer`, or chosen from `/manage`
with manual parser selection. Retain each input's `minimal-status.jsonl`
basename: the plug-in deliberately requires its advertised artifact name.

Finalize plug-in sources and generated type stubs before admission. Stop old
workers before changing a deployment that shares a state directory. Exact
provider/package pins are intentionally revalidated, and an old worker cannot
publish a revision under a different composition policy. Preserve any failure
journal and explicitly resume/re-admit under the matching deployment.

At `/manage`, connect with tenant `demo-workbench` and principal
`local-reviewer`. Select project `core-coverage`, workspace `workflow`.

1. **Data & revisions:** compare the two findings. Before has two non-up
   interfaces; after has none. Inspect three resources and one `corresponds_to`
   projection. They remain independent resource IDs. Projection basis and
   execution-plan digests are retained; a projection does not assert timed
   presence at the selected reconstruction moment.
2. **Sessions:** create a session; add the before and after revision IDs as two
   different members of the same node. Freeze a snapshot, change the live
   session, and inspect the unchanged snapshot vector.
3. **Imports:** use the generated peer input to try manual candidate selection.
   The evidence auxiliary must never be offered as a parser. Inspect processing
   events and the exact parser identity before choosing it.
4. **Administration:** inspect disabled retention and its advisory preview.
   Nothing is deleted by this walkthrough. Tenant administration must not grant
   process-wide diagnostics; `-GrantInstanceOperator` is a separate explicit
   loopback-only option.
5. **Private analysis:** first verify that a new workspace's disabled policy
   prevents runner execution. If desired, explicitly permit only `client_safe`
   with `in_process` for this synthetic workspace. In `/analysis`, enter the same
   scope/principal, select the published revisions and `General evidence review`,
   then choose `demo.scripted-evidence-walk` and submit once. Expect a clearly
   labeled scripted report with real source and auxiliary-provider citations,
   not a diagnosis, proposal or automatic annotation. Disable disclosure again
   when finished. The host never configures a public-model service.

The runner ID/version and configuration/instruction digests are versioned demo
identities. Any future change to scripted semantics must bump the runner
version/profile identity so durable replay does not silently select new logic.

## Route and packet walkthrough

The **Trace scenario** selector is visible above the endpoint controls. Its
description is visible text, not a hover-only tooltip. Selecting a scenario
applies its advertised endpoints/start; shareable URLs preserve explicit
overrides. **Advanced trace options** exposes the backend-advertised maximum
hops and recursion bounds. A small budget must produce a bounded result, not
invent a successful path. **Restore trace limits** restores the advertised
defaults without changing endpoints, scenario, direction or steering; press
**Trace route** afterwards to compare results. Editing limits invalidates the
old result instead of leaving a stale verdict visible.

The overall reachability/comparison banner remains above the graph in **All
paths**, even when no individual path is selected. Selecting a path opens its
own resolution and packet details; the overall verdict and a candidate's
individual disposition are distinct.

| Scenario | Expected first MTU/continuity observation |
| --- | --- |
| `packet-mtu-fit` | 1420 + 20 = 1440 bytes; fits 1500; delivered |
| `packet-mtu-exact` | 1480 + 20 = 1500 bytes; equality fits; delivered |
| `packet-mtu-drop` | 1490 + 20 = 1510 bytes; exceeds 1500; dropped |
| `packet-mtu-incomparable` | Wire-size and IP-size bases differ; `unknown_basis_mismatch`, not a proven MTU failure |
| `packet-native-ip-incomplete` | Partial transit capture; `unknown_incomplete` persists despite terminal delivery |

Try both directions, expand packet state and select a transition. The inspector
shows before/after packet-size basis identifiers alongside the declared MTU
limit and basis; missing or incomplete facts stay explicit. A delivered
packet and complete capture are different facts. The existing normal IP,
SR-MPLS/PHP, SRv6, nested-VPN, loop, split-horizon and transit-start cases remain
available in the same selector and on the same ten-node fabric.
