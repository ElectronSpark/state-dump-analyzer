# State Dump Generator

State Dump Generator is a standalone, local scenario studio for creating
temporal router state dumps. Draw the physical situation you want to reproduce,
schedule what each router observes, and export one dump per router inside a
deterministic assembly.

It is intentionally independent from Router State Lab, the demo, and analyzer
plug-ins. It uses only Python's standard library at runtime and does not import
or invoke analyzer code.

> [!IMPORTANT]
> A saved authoring project and a generated dump are deliberately different.
> The project JSON is private ground truth: it can contain the supposed physical
> topology, canvas positions, propagation intent, and all planned changes.
> Generated node dumps contain only that router's final status and node-local
> history. They never contain the physical topology, private medium IDs,
> scenario, oracle, propagation plan, or global participant list.

Router State Lab keeps its future demo authoring source at
[`../demo/router-state-lab-default.scenario.json`](../demo/router-state-lab-default.scenario.json).
That file is an ordinary save from this tool. This package can edit, validate,
preview, and compile it, but it still does not depend on or invoke the analyzer,
demo, or any plug-in. The demo crosses the boundary in the other direction by
reading the saved JSON with its own standard-library data adapter.

## Quick start

Python 3.12 or newer is required. The included Conda environment is the easiest
way to run the editor.

### Windows

From this directory:

```powershell
.\launch.ps1
```

The launcher finds Conda in `PATH` or a normal per-user Anaconda/Miniconda
installation, then creates the environment automatically when it does not
exist. A Command Prompt wrapper is also available:

```bat
launch.cmd
```

To choose another port or avoid opening a browser:

```powershell
.\launch.ps1 -Port 8877 -NoBrowser
```

### Linux or WSL

```bash
./launch.sh
```

Like the Windows launcher, `launch.sh` creates the
`state-dump-generator` Conda environment when it is missing. It does not open a
browser by default. Open
[http://127.0.0.1:8770](http://127.0.0.1:8770), use
`./launch.sh --open` to open it automatically, or use
`./launch.sh --port 8877` to select another port.

The editor is unauthenticated and deliberately refuses non-loopback bind
addresses. It is for local authoring, not network deployment.

## Author a scenario in the web editor

The editor follows the familiar GNS2 pattern:

1. Drag routers, hosts, switches, and shared media onto the canvas.
2. Connect objects and name the router-side ports.
3. Move the time cursor to when a change should occur.
4. Add, edit, or remove a node-local event. Choose whether it updates that
   node's final snapshot.
5. Optionally preview and apply best-effort propagation. Adjust the targets,
   delay, jitter, and outcome before accepting the generated observations.
6. Validate the project, save its JSON, and generate the dump assembly.

To work on the bundled Router State Lab scenario, click **Open** and choose
`demo/router-state-lab-default.scenario.json` from the repository checkout.
That saved file, rather than a generated TGZ, is the durable source for future
demo generations.

Changing physical truth does not silently pretend that all routers learned the
change at once. Observations are separate temporal events, so a link can be
physically down while one router still reports a neighbor as up. Events can be
local, delayed, suppressed, partial, duplicated, or explicitly failed.

The final snapshot is calculated by replaying each node's status-changing
events through the capture time. Editing an event in the past therefore changes
the reconstructed history while later events still determine the latest state.
An attempted event may also be retained as a log without changing the snapshot.

## Command-line workflow

The commands in this section assume the current directory is
`state-dump-generator/`. Install the package in a Python 3.12 environment:

```bash
python -m pip install -e .
```

Create a blank authoring project:

```bash
state-dump-generator new lab.json
```

Validate it before generation:

```bash
state-dump-generator validate lab.json
```

Generate an assembly with one node dump per router:

```bash
state-dump-generator generate lab.json --output lab-state-dumps.tgz
```

Run the browser editor:

```bash
state-dump-generator serve --open
```

The module form is equivalent:

```bash
python -m state_dump_generator serve --port 8877 --open
```

`new` refuses to overwrite an existing file unless `--force` is supplied.
`validate` emits a machine-readable JSON report and returns a nonzero status
for an invalid project. `generate` validates before writing and replaces its
regular-file destination atomically. It refuses an output path that traverses
a symbolic link or Windows junction.

### Validate, preview, and compile the canonical demo save

From the Router State Lab repository root, these PowerShell commands are
copy-paste ready:

```powershell
python -m pip install -e .\state-dump-generator
python -m state_dump_generator validate .\demo\router-state-lab-default.scenario.json
python -m state_dump_generator serve --open
```

The last command starts the studio. Click **Open**, select the canonical JSON,
and use the scenario-time control to preview physical state and scheduled local
observations. Stop the server with `Ctrl+C` when finished.

To compile the authoring save into the independent tool's small neutral
assembly:

```powershell
python -m state_dump_generator generate `
  .\demo\router-state-lab-default.scenario.json `
  --output .\artifacts\router-state-lab-default.node-dumps.tgz
```

This output intentionally does not contain Router State Lab's full-scale
filler or plug-in projections. To generate and launch the comprehensive demo,
use its separate materializer and core launcher:

```powershell
python -X utf8 -m rsl_demo_generator `
  --output .\demo\fixtures\router-state-lab-demo.tgz
.\scripts\launch_demo.cmd -NoBrowser
```

The canonical timeline starts at `2025-10-05 16:00:00 UTC`. Useful preview
boundaries include `+30 s` (route creation), `+90 s` to `+108 s` (physical
failure followed by asymmetric, stale, and failed observations), `+180 s` to
`+304 s` (local detach and reattach), `+420 s` to `+535 s` (delayed Ottawa
failure and recovery), and `+610 s` (the final next-hop update). See the
[demo guide](../demo/README.md#past-time-reconstruction-checkpoints) for exact
node and resource expectations.

## What is in a saved project?

The authoring JSON is a versioned, generator-owned format. Its main concepts
are:

- **Objects** — routers that produce dumps plus hosts, switches, and shared
  media used to express physical intent. Canvas positions are authoring data.
- **Physical links** — endpoint and port pairs with an initial state. Their
  status can change over scenario time.
- **Node-local events** — an observation time, observing router, subject,
  action, outcome, structured payload, optional source-log text, and whether
  the event is replayed into final state.
- **Propagation intent** — target scope, delay, jitter, cadence, and outcome
  used to schedule editable observations from a selected event.
- **Capture time** — the latest point replayed to produce each router's final
  snapshot.

Every event has stable identity so it can be edited or removed without
rewriting unrelated history. The saved project is the source of truth for
regeneration; do not send it to the analyzer as though it were a router dump.

### Attachment export boundary

An attachment can hold private editor metadata and separately declare the
node-local evidence that may enter its router's dump:

```json
{
  "node_id": "r1",
  "port_id": "xe-0/0/0",
  "properties": {
    "canvas_note": "authoring-only",
    "supposed_failure_domain": "west"
  },
  "node_local_observation": {
    "resource_id": "interface:r1-xe-0/0/0.310",
    "resource_type": "virtual-interface",
    "observed_state": "up",
    "properties": {
      "interface_name": "xe-0/0/0.310",
      "subnet_prefix": "192.0.2.0/31",
      "vlan_id": 310
    }
  }
}
```

Only `node_local_observation` is eligible for interface snapshot and propagated
physical-observation records. Attachment-level `properties` stay in the saved
authoring project and private preview; the simulator never copies them into a
node dump. This is true even when `node_local_observation` is absent. The
top-level attachment `resource_id` (or legacy `local_resource_id`, then the
port ID) is retained only as the fallback identity of that node's local
interface record. Top-level `properties` and `observed_state` are not promoted
into node-local evidence.

Existing schema-v1 saves can still be opened, but authors must move every value
that should cross the dump boundary into an explicit
`node_local_observation`. Saving writes that explicit envelope; it does not
silently reclassify authoring metadata as router evidence. The envelope is
neutral generator JSON and does not depend on analyzer or plug-in types.
Forbidden authoring keys are rejected recursively inside export-eligible
values. An exact private medium ID is rejected when it appears in any
identity-bearing field: built-in fields and plug-in-defined `*_id`, `*_ids`,
`*_key`, or `*_keys` fields all participate. The same ordinary text in a
non-identity note is not treated as topology identity.

## Best-effort propagation

The generator is not a protocol emulator. Propagation is a general scheduling
aid that turns an initiating change into proposed node-local observations.
Review the preview, then keep, edit, delay, fail, or remove each proposed event.
That makes successful convergence and intentionally broken behavior equally
expressible.

The editor includes reusable starting patterns:

| Pattern | What it helps model |
|---|---|
| Clean link flap | Physical down/up with converged observations |
| One-sided detection | Only one endpoint notices a change |
| Delayed convergence | Different routers learn the same change later |
| Stale neighbor | Physical and reported adjacency disagree |
| Failed update | A logged attempt that does not change final state |
| Next-hop change | Dependency replacement and route churn |
| Node restart | Withdrawal and restoration burst |
| Clock skew | Bounded differences in local event timestamps |
| Log gap | Missing node-local evidence |
| Partial multi-access failure | One participant or member lags behind |

Because generated observations remain ordinary editable events, patterns can be
combined. For example, apply a link flap, suppress one endpoint's propagation,
delay a transit node, and turn one route update into a failed attempt.

### Capture horizon and cadence

Validation computes the latest possible generated observation using the actual
eligible target set, delay, absolute jitter bound, and cadence:

- `parallel` schedules every target from the same base delay;
- `serial` advances each target by another base-delay slot (at least 1 ms);
- `waves` advances each pair of targets by half a base-delay slot (at least
  1 ms).

When that conservative horizon is later than `capture_time_ns`, validation
returns a warning rather than changing the scenario. Observations after capture
remain in the authoring plan but do not enter final snapshots or exported
history. If capture time is omitted, the loader chooses a default at least one
second beyond the calculated horizon. Explicit capture time always wins, which
lets an author deliberately test incomplete propagation.

## Generated archive layout

`generate` writes a deterministic outer TGZ:

```text
lab-state-dumps.tgz
├── manifest.json
└── nodes/
    ├── router-a.tgz
    ├── router-b.tgz
    └── ...
```

The outer manifest identifies the generated node archives and their checksums.
It contains no topology or scenario model, private authoring medium IDs, or
global participant list. Each nested node TGZ contains:

```text
manifest.json
status/final-state.jsonl
status/final-state.txt
logs/history.jsonl
```

`status/final-state.*` is the final node-local snapshot at capture time.
`logs/history.jsonl` is the timestamp-ordered local history used to reconstruct
past status. The text status file is convenient for inspecting or adapting the
output; JSON Lines preserves structured values.

Every exported timestamp uses the node's own clock domain: `captured_at_ns`,
history `timestamp_ns`, and final-state `updated_at_ns` all include that node's
configured offset. The private editor timeline is not exported as an absolute
clock oracle. History rows also carry `source_sequence`, which preserves the
author-defined order of changes that share one local timestamp.

The generation boundary rejects forbidden authoring/oracle keys recursively
and also rejects a private physical-medium identifier if it is copied into an
export-eligible node-local identity field, including a plug-in-defined
`*_id` or `*_key`. A generated dump therefore contains only the attachment
evidence declared in
`node_local_observation`, such as an interface, VLAN, or subnet observation,
but not attachment-level authoring metadata or the editor's physical medium
identity. The writer produces stable ordering, ownership metadata, and gzip
headers so identical projects generate identical bytes.

Automatic propagation inherits a failed, stale, suppressed, or dropped parent
outcome unless the author explicitly overrides the outcome for a target. This
prevents a failed initiating update from silently becoming a successful remote
state change. The editor remains a scheduling aid rather than a protocol
emulator.

Project inputs, static assets, and output targets are checked lexically before
path resolution; symbolic-link and junction traversal is refused at those file
boundaries. The local HTTP editor bounds body reads and closes a connection
when rejecting a POST before consuming its body, so HTTP/1.1 keep-alive cannot
reinterpret unread bytes as another request.

## Independence and integration

This project owns scenario authoring, generic propagation scheduling, replay,
and its neutral output format. It does not know how Router State Lab plug-ins
name resources or interpret vendor protocols. Conversely, the analyzer core
does not depend on this generator.

A consumer can read the neutral JSON Lines directly or implement a separate
adapter for its own dump ingestion format. Router State Lab's demo does exactly
that: its standard-library adapter reads the canonical save through the JSON
file boundary, derives shared domains only from repeated node-local attachment
evidence, and its separate materializer adds deterministic scalable filler and
plug-in projections. The demo records the exact save digest in its assembly and
node manifests, alongside a fingerprint of its independent materializer and
demo plug-in code, so launch preparation invalidates a TGZ after either the
save or the interpretation logic changes.

Any adapter remains outside this package. Physical ground truth, private medium
IDs, and global participant lists must not be copied into the resulting node
dumps.

## Development

Run the standalone tests from this directory:

```bash
python -m unittest discover -s tests -v
```

The test suite verifies deterministic archives, per-node isolation, recursive
rejection of authoring truth, safe archive paths, the local web API, and the
absence of analyzer/demo/plugin runtime dependencies.
